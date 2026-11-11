import subprocess as sp
from types import SimpleNamespace

from kisiac import update


def test_update_system_packages_prefers_deb_and_falls_back_to_snap(monkeypatch) -> None:
    calls = []

    monkeypatch.setattr(update, "default_system_software", [])
    monkeypatch.setattr(
        update.Config, "get_instance", lambda: SimpleNamespace(system_software=["htop", "lazygit"])
    )
    monkeypatch.setattr(
        update.UpdateHostSettings, "get_instance", lambda: SimpleNamespace(skip_system_upgrade=False)
    )
    monkeypatch.setattr(update, "exists_cmd", lambda cmd, host, sudo: True)

    def fake_run_cmd(*args, **kwargs):
        cmd = args[0]
        calls.append(cmd)
        if cmd[:3] == ["apt-cache", "show", "--no-all-versions"]:
            if cmd[3] == "htop":
                return sp.CompletedProcess(cmd, 0, stdout="Package: htop", stderr="")
            return sp.CompletedProcess(cmd, 100, stdout="", stderr="No packages found")
        if cmd == ["snap", "list", "lazygit"]:
            return sp.CompletedProcess(cmd, 1, stdout="", stderr="")
        return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(update, "run_cmd", fake_run_cmd)

    update.update_system_packages("localhost")

    assert ["apt-get", "--yes", "update"] in calls
    assert ["apt-get", "--yes", "upgrade"] in calls
    assert ["apt-get", "--yes", "install", "htop"] in calls
    assert ["snap", "list", "lazygit"] in calls
    assert ["snap", "install", "lazygit"] in calls


def test_update_system_packages_installs_snapd_when_missing(monkeypatch) -> None:
    calls = []
    snap_checks = iter([False, True])

    monkeypatch.setattr(update, "default_system_software", [])
    monkeypatch.setattr(
        update.Config, "get_instance", lambda: SimpleNamespace(system_software=["lazygit"])
    )
    monkeypatch.setattr(
        update.UpdateHostSettings, "get_instance", lambda: SimpleNamespace(skip_system_upgrade=True)
    )
    monkeypatch.setattr(update, "exists_cmd", lambda cmd, host, sudo: next(snap_checks))

    def fake_run_cmd(*args, **kwargs):
        cmd = args[0]
        calls.append(cmd)
        if cmd[:3] == ["apt-cache", "show", "--no-all-versions"]:
            return sp.CompletedProcess(cmd, 100, stdout="", stderr="No packages found")
        if cmd == ["snap", "list", "lazygit"]:
            return sp.CompletedProcess(cmd, 1, stdout="", stderr="")
        return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(update, "run_cmd", fake_run_cmd)

    update.update_system_packages("localhost")

    assert ["apt-get", "--yes", "install", "snapd"] in calls
    assert ["snap", "install", "lazygit"] in calls
