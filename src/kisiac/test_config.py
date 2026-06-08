import base64
import platform
import subprocess as sp
from pathlib import Path
from typing import Any

import yaml

from kisiac.common import UserError, log_msg
from kisiac.runtime_settings import TestConfigSettings

_KNOWN_RUNTIMES = ["docker", "podman", "apptainer", "udocker"]
_CONTAINER_REPO_PATH = "/kisiac-config"


def detect_runtime() -> str:
    for runtime in _KNOWN_RUNTIMES:
        try:
            sp.run([runtime, "--version"], check=True, capture_output=True)
            log_msg(f"Auto-detected container runtime: {runtime}")
            return runtime
        except (FileNotFoundError, sp.CalledProcessError):
            continue
    raise UserError(
        "No container runtime found. Please install one of: "
        + ", ".join(_KNOWN_RUNTIMES)
    )


def _build_init_script(config_yaml: str, upgrade: bool) -> str:
    skip_arg = "" if upgrade else "--skip-system-upgrade"
    config_b64 = base64.b64encode(config_yaml.encode()).decode()
    lines = [
        "set -e",
        "apt-get update -q",
        "apt-get install -y -q python3 python3-pip git",
        "pip3 install --quiet kisiac",
        f"printf '%s' '{config_b64}' | base64 -d > /etc/kisiac.yaml",
        f"kisiac --non-interactive update-hosts {skip_arg} localhost",
        f"kisiac --non-interactive update-hosts {skip_arg} localhost",
    ]
    return "\n".join(lines) + "\n"


def _build_container_cmd(
    runtime: str,
    image: str,
    local_repo: Path | None,
    hostname: str,
    script_b64: str,
) -> list[str]:
    inner_cmd = f"printf '%s' '{script_b64}' | base64 -d | bash"
    match runtime:
        case "docker" | "podman":
            cmd = [runtime, "run", "--rm", "--privileged", "-h", hostname]
            if local_repo is not None:
                cmd += ["-v", f"{local_repo}:{_CONTAINER_REPO_PATH}:ro"]
            cmd += [image, "bash", "-c", inner_cmd]
        case "udocker":
            cmd = ["udocker", "run", "--rm", "-h", hostname]
            if local_repo is not None:
                cmd += ["-v", f"{local_repo}:{_CONTAINER_REPO_PATH}"]
            cmd += [image, "bash", "-c", inner_cmd]
        case "apptainer":
            cmd = ["apptainer", "exec", "--writable-tmpfs", "--fakeroot"]
            if local_repo is not None:
                cmd += ["--bind", f"{local_repo}:{_CONTAINER_REPO_PATH}"]
            cmd += [f"docker://{image}", "bash", "-c", inner_cmd]
        case _:
            raise UserError(
                f"Unknown container runtime: {runtime!r}. "
                "Choose one of: " + ", ".join(_KNOWN_RUNTIMES)
            )
    return cmd


def _build_config_yaml(repo_ref: str, extra_config: dict[str, Any]) -> str:
    config: dict[str, Any] = {"repo": repo_ref}
    config.update(extra_config)
    return yaml.dump(config)


def test_config() -> None:
    settings = TestConfigSettings.get_instance()

    runtime = settings.runtime or detect_runtime()

    if runtime not in _KNOWN_RUNTIMES:
        raise UserError(
            f"Unknown container runtime: {runtime!r}. "
            "Choose one of: " + ", ".join(_KNOWN_RUNTIMES)
        )

    hostname = settings.hostname or platform.node()

    # Determine whether the repo is a local path or a remote URL.
    repo_path = Path(settings.repo)
    if repo_path.exists():
        local_repo = repo_path.resolve()
        repo_ref = _CONTAINER_REPO_PATH
    else:
        local_repo = None
        repo_ref = settings.repo

    # Load any additional config provided by the user.
    extra_config: dict[str, Any] = {}
    if settings.kisiac_config:
        config_path = Path(settings.kisiac_config)
        if not config_path.exists():
            raise UserError(f"Config file not found: {config_path}")
        with open(config_path) as f:
            loaded = yaml.safe_load(f)
        if isinstance(loaded, dict):
            extra_config = loaded

    config_yaml = _build_config_yaml(repo_ref, extra_config)
    script = _build_init_script(config_yaml, settings.upgrade)
    script_b64 = base64.b64encode(script.encode()).decode()

    cmd = _build_container_cmd(runtime, settings.image, local_repo, hostname, script_b64)

    log_msg(
        f"Testing config repo {settings.repo!r} using {runtime} "
        f"(image: {settings.image}, hostname: {hostname}) ..."
    )
    try:
        sp.run(cmd, check=True)
    except sp.CalledProcessError as e:
        raise UserError(
            f"Container test failed with exit code {e.returncode}"
        ) from e

    log_msg("Config test passed!")
