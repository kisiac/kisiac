import os
import shlex
import subprocess
from types import SimpleNamespace

import pytest

from kisiac import common, config
from kisiac.runtime_settings import GlobalSettings


@pytest.fixture
def sudo_config(monkeypatch, tmp_path):
    config_path = tmp_path / "kisiac.yaml"
    config_path.write_text("sudo_prompt: true\n")
    monkeypatch.setattr(config, "config_file_path", config_path)
    monkeypatch.setattr(common, "_sudo_passwords", {})
    monkeypatch.setattr(
        config.Config, "get_instance", lambda: SimpleNamespace(sudo_prompt=True)
    )


@pytest.mark.parametrize("value", [True, False])
def test_sudo_prompt_reads_merged_config(monkeypatch, tmp_path, value):
    config_path = tmp_path / "kisiac.yaml"
    config_path.write_text("repo: test\nsudo_prompt: false\n")
    monkeypatch.setattr(config, "config_file_path", config_path)
    monkeypatch.setattr(
        config,
        "Files",
        lambda _config: SimpleNamespace(get_config=lambda: {"sudo_prompt": value}),
    )
    assert config.Config().sudo_prompt is value


def test_sudo_prompt_defaults_to_false_and_checks_type():
    instance = object.__new__(config.Config)
    instance._config = {}
    assert instance.sudo_prompt is False
    instance._config["sudo_prompt"] = "true"
    with pytest.raises(common.UserError, match="sudo_prompt key"):
        _ = instance.sudo_prompt


def test_sudo_disabled_preserves_command(monkeypatch, tmp_path):
    config_path = tmp_path / "kisiac.yaml"
    config_path.write_text("sudo_prompt: false\n")
    monkeypatch.setattr(config, "config_file_path", config_path)
    monkeypatch.setattr(
        config.Config, "get_instance", lambda: SimpleNamespace(sudo_prompt=False)
    )
    calls = []
    monkeypatch.setattr(
        common.sp, "run", lambda *args, **kwargs: calls.append((args, kwargs))
    )
    monkeypatch.setattr(
        common,
        "provide_password",
        lambda *_args: pytest.fail("unexpected password prompt"),
    )
    common.run_cmd(["cat"], sudo=True, input="payload")
    assert calls[0][0][0] == ["sudo", "bash", "-c", "cat"]
    assert calls[0][1]["input"] == "payload"


@pytest.mark.usefixtures("sudo_config")
def test_remote_sudo_prompts_once_per_host_and_never_logs_password(monkeypatch, capsys):
    prompts = []
    calls = []
    monkeypatch.setattr(
        common, "provide_password", lambda *args: prompts.append(args) or "secret"
    )

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args[0], 0, stdout="", stderr="")

    monkeypatch.setattr(common.sp, "run", fake_run)

    common.run_cmd(["cat"], host="server", sudo=True, input="payload")
    common.run_cmd(["echo", "hello world"], host="server", sudo=True)
    common.run_cmd(["cat"], host="other", sudo=True)

    assert len(prompts) == 2
    assert all(prompt[1] == "KISIAC_SUDO_PASSWORD" for prompt in prompts)
    remote = calls[0][0][0]
    assert remote[:2] == ["ssh", "server"]
    assert shlex.split(remote[2])[-1] == "cat"
    assert calls[0][1]["input"] == "secret\npayload"
    assert "secret" not in capsys.readouterr().err
    assert all("secret" not in str(call[0]) for call in calls)


@pytest.mark.usefixtures("sudo_config")
@pytest.mark.parametrize("password_required", [True, False])
@pytest.mark.parametrize("host", ["localhost", "remote"])
def test_sudo_keeps_command_stdin_separate(
    monkeypatch, tmp_path, password_required, host
):
    sudo = tmp_path / "sudo"
    sudo.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-S" ]; then\n'
        f'  echo "$PPID" > "{tmp_path / "parent"}"\n'
        + (
            '  IFS= read -r password\n  [ "$password" = secret ] || exit 1\n'
            if password_required
            else ""
        )
        + "  exit 0\n"
        "fi\n"
        f'[ "$(cat "{tmp_path / "parent"}")" = "$PPID" ] || exit 2\n'
        'shift\nexec "$@"\n'
    )
    sudo.chmod(0o755)
    ssh = tmp_path / "ssh"
    ssh.write_text('#!/bin/sh\nshift\nexec sh -c "$1"\n')
    ssh.chmod(0o755)
    monkeypatch.setenv("KISIAC_SUDO_PASSWORD", "secret")
    monkeypatch.setattr(
        GlobalSettings, "get_instance", lambda: SimpleNamespace(non_interactive=True)
    )
    env = dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}")

    result = common.run_cmd(["cat"], sudo=True, input="payload\n", env=env, host=host)
    assert result.stdout == "payload\n"


@pytest.mark.usefixtures("sudo_config")
def test_sudo_password_required_in_non_interactive_mode(monkeypatch):
    monkeypatch.delenv("KISIAC_SUDO_PASSWORD", raising=False)
    monkeypatch.setattr(
        GlobalSettings, "get_instance", lambda: SimpleNamespace(non_interactive=True)
    )
    with pytest.raises(common.UserError, match="KISIAC_SUDO_PASSWORD"):
        common.run_cmd(["true"], sudo=True)


@pytest.mark.usefixtures("sudo_config")
def test_sudo_authentication_failure_is_reported(monkeypatch):
    monkeypatch.setattr(common, "provide_password", lambda *_args: "secret")
    monkeypatch.setattr(
        common.sp,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            subprocess.CalledProcessError(1, args[0], stderr="authentication failed")
        ),
    )
    with pytest.raises(common.UserError, match="authentication failed") as error:
        common.run_cmd(["true"], sudo=True)
    assert "secret" not in str(error.value)


@pytest.mark.usefixtures("sudo_config")
def test_sudo_authentication_failure_is_not_treated_as_missing_command(monkeypatch):
    monkeypatch.setattr(common, "provide_password", lambda *_args: "secret")
    monkeypatch.setattr(
        common.sp,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 125, stdout="", stderr="bad password" + common._sudo_auth_error
        ),
    )
    with pytest.raises(common.UserError, match="Sudo authentication failed"):
        common.exists_cmd("zpool", host="localhost", sudo=True)
    assert common._sudo_passwords == {}
