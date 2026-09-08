import subprocess as sp

from kisiac import check


def test_parse_zpool_status() -> None:
    output = """
  pool: tank
 state: DEGRADED
status: One or more devices are faulted in response to persistent errors.
        Sufficient replicas exist for the pool to continue functioning.
action: Replace the faulted device, and then run 'zpool clear'.
  scan: resilver in progress since Mon Jun  8 10:00:00 2026
config:
"""
    parsed = check.parse_zpool_status(output)
    assert parsed["state"] == "DEGRADED"
    assert parsed["status"] == (
        "One or more devices are faulted in response to persistent errors. "
        "Sufficient replicas exist for the pool to continue functioning."
    )
    assert parsed["action"] == "Replace the faulted device, and then run 'zpool clear'."
    assert parsed["scan"] == "resilver in progress since Mon Jun  8 10:00:00 2026"


def test_check_zfs_health_reports_action_items(monkeypatch) -> None:
    logs = []

    def fake_exists_cmd(cmd: str, host: str, sudo: bool) -> bool:
        return cmd == "zpool"

    def fake_run_cmd(*args, **kwargs):
        cmd = args[0]
        if cmd == ["zpool", "list", "-H", "-o", "name"]:
            return sp.CompletedProcess(cmd, 0, stdout="tank\n", stderr="")
        if cmd == ["zpool", "status", "tank"]:
            return sp.CompletedProcess(
                cmd,
                0,
                stdout=(
                    "  pool: tank\n"
                    " state: DEGRADED\n"
                    "action: Replace the faulted device.\n"
                    "  scan: resilver in progress since Mon Jun  8 10:00:00 2026\n"
                ),
                stderr="",
            )
        raise AssertionError(f"Unexpected command {cmd}")

    def fake_log(*msgs, host=None) -> None:
        logs.append(" ".join(map(str, msgs)))

    monkeypatch.setattr(check, "exists_cmd", fake_exists_cmd)
    monkeypatch.setattr(check, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(check, "log_msg", fake_log)

    check.check_zfs_health("localhost")

    assert logs[0] == "ZFS pool tank health: DEGRADED"
    assert (
        logs[1]
        == "ZFS pool tank action items: Replace the faulted device.; "
        "resilver in progress since Mon Jun  8 10:00:00 2026"
    )
