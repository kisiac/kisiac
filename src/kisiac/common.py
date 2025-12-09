from pathlib import Path
import subprocess as sp
import sys
from typing import Any, Callable, Self, Sequence
import os

import inquirer


cache = Path("~/.cache/kisiac").expanduser()


def multiline_input(msg: str) -> str:
    lines = []
    print(msg, "Hit Ctrl+D to finish.")
    while True:
        try:
            lines.append(input())
        except EOFError:
            return "\n".join(lines)


def handle_key_error(msg: str) -> Callable:
    def decoator(func: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except KeyError as e:
                raise UserError(f"{msg}: {e}") from e

        return wrapper

    return decoator


class Singleton:
    @classmethod
    def get_instance(cls, *args, **kwargs) -> Self:
        if not hasattr(cls, "_instance") or cls._instance is None:
            cls._instance = cls(*args, **kwargs)
        return cls._instance


def confirm_action(desc: str) -> bool:
    from kisiac.runtime_settings import GlobalSettings

    if GlobalSettings.get_instance().non_interactive:
        return True

    response = inquirer.prompt(
        [inquirer.Checkbox("action", message=desc, choices=["yes", "no"])]
    )
    assert response is not None
    return response["action"] == "yes"


def provide_password(msg: str) -> str:
    from kisiac.runtime_settings import GlobalSettings

    password = os.environ.get("KISIAC_ENCRYPTION_PASSWORD")

    if GlobalSettings.get_instance().non_interactive and password is None:
        raise UserError(
            "No password provided via KISIAC_ENCRYPTION_PASSWORD but non-interactive mode activated."
        )

    if password is not None:
        return password

    while True:
        response = inquirer.prompt(
            [
                inquirer.Password("password", message=msg),
                inquirer.Password("confirm_password", message="Confirm password"),
            ]
        )
        assert response is not None
        if response["password"] != response["confirm_password"]:
            log_msg("Passwords do not match, try again.")
        else:
            return response["password"]


def exists_cmd(cmd: str, host: str, sudo: bool) -> bool:
    try:
        run_cmd(["which", cmd], host=host, sudo=sudo, user_error=False)
        return True
    except sp.CalledProcessError:
        return False


def log_msg(*msgs: Any, host: str | None = None) -> None:
    if host is not None:
        msgs = [f"[{host}]", *msgs]
    print(" ".join(map(str, msgs)), file=sys.stderr)


def cmd_to_str(*cmds: list[str]) -> str:
    return "\n".join(" ".join(map(str, cmd)) for cmd in cmds)


def run_cmd(
    cmd: list[str | Path],
    input: str | None = None,
    host: str = "localhost",
    env: dict[str, Any] | None = None,
    sudo: bool = False,
    user_error: bool = True,
    user_error_msg: str = "",
    check: bool = True,
) -> sp.CompletedProcess[str]:
    """Run a system command using subprocess.run and check for errors."""
    # TODO check quotation!
    cmd = list(map(str, cmd))
    if sudo:
        cmd = ["sudo", "bash", "-c", f"{' '.join(cmd)}"]
    if host != "localhost":
        if sudo:
            cmd = ["ssh", host, f"sudo bash -c '{' '.join(cmd)}'"]
        else:
            cmd = ["ssh", host, f"{' '.join(cmd)}"]
    log_msg("Running command", cmd_to_str(cmd), host=host)
    try:
        return sp.run(
            cmd,
            check=check,
            text=True,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
            input=input,
            env=env,
        )
    except sp.CalledProcessError as e:
        if user_error:
            if user_error_msg:
                user_error_msg += ": "
            err = e.stderr
            if not err:
                err = e.stdout
            raise UserError(
                f"{user_error_msg}Error occurred while running command '{' '.join(cmd)}': {err}"
            ) from e
        else:
            raise


class UserError(Exception):
    """Base class for user-related errors."""

    pass


def check_type(item: str, value: Any, expected_type: Any) -> None:
    if not isinstance(value, expected_type):
        raise UserError(
            f"Expecting {expected_type} for {item}, found "
            f"value {value} of type {type(value)}."
        )


class HostAgnosticPath:
    def __init__(
        self, path: str | Path, host: str = "localhost", sudo: bool = False
    ) -> None:
        self.path = Path(path)
        self.host = host
        self.sudo = sudo
        if self.is_local_and_user():
            # if non local or sudo, shell commands will be used, which expand
            # the ~ operator automatically
            self.path = self.path.expanduser()

    def read_text(self) -> str:
        if self.is_local_and_user():
            return self.path.read_text()
        else:
            return self._run_cmd(["cat", str(self.path)]).stdout

    def write_text(self, content: str) -> None:
        if self.is_local_and_user():
            self.path.write_text(content)
        else:
            self._run_cmd(
                ["tee", str(self.path)],
                input=content,
            )

    def mkdir(self) -> None:
        if self.is_local_and_user():
            self.path.mkdir(parents=True, exist_ok=True)
        else:
            self._run_cmd(["mkdir", "-p", str(self.path)])

    def chmod(self, *mode: str, recursive: bool = True) -> None:
        self._chperm("chmod", ",".join(mode), recursive=recursive)

    def chown(self, user: str | None, group: str | None = None) -> None:
        if user is not None:
            owner = f"{user}:{group}" if group else user
            self._chperm("chown", owner)
        elif group is not None:
            self._chperm("chgrp", group)
        else:
            raise ValueError("Either user or group must be provided.")

    def _chperm(self, cmd: str, arg: str, recursive: bool = True) -> None:
        args = [arg]
        if recursive and self.is_dir():
            args = ["-R", *args]
        self._run_cmd([cmd, *args, str(self.path)])

    def is_local_and_user(self) -> bool:
        return self.host == "localhost" and not self.sudo

    def _run_cmd(
        self, cmd: list[str], input: str | None = None, user_error: bool = True
    ) -> sp.CompletedProcess[str]:
        return run_cmd(
            cmd,
            input=input,
            host=self.host,
            sudo=self.sudo,
            user_error=user_error,
        )

    def exists(self) -> bool:
        if self.is_local_and_user():
            return self.path.exists()
        else:
            try:
                self._run_cmd(
                    ["test", "-e", str(self.path)],
                    user_error=False,
                )
                return True
            except sp.CalledProcessError:
                return False

    def is_dir(self) -> bool:
        if self.is_local_and_user():
            return self.path.is_dir()
        else:
            try:
                self._run_cmd(
                    ["test", "-d", str(self.path)],
                    user_error=False,
                )
                return True
            except sp.CalledProcessError:
                return False

    def with_suffix(self, suffix: str) -> Self:
        return type(self)(self.path.with_suffix(suffix), host=self.host, sudo=self.sudo)

    @property
    def parents(self) -> Sequence[Self]:
        return [
            type(self)(parent, host=self.host, sudo=self.sudo)
            for parent in self.path.parents
        ]

    def __truediv__(self, other: Any) -> Self:
        return type(self)(self.path / other, host=self.host, sudo=self.sudo)

    def __rtruediv__(self, other: Any) -> Self:
        return type(self)(other / self.path, host=self.host, sudo=self.sudo)

    def __str__(self) -> str:
        if self.host == "localhost":
            return str(self.path)
        else:
            return f"{self.host}:{self.path}"
