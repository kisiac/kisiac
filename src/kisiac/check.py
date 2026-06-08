import json

from kisiac.common import UserError, exists_cmd, log_msg, run_cmd
from kisiac.filesystems import DeviceInfos
from kisiac.lvm import LVMSetup


def parse_zpool_status(output: str) -> dict[str, str | None]:
    fields = {
        "state": None,
        "status": None,
        "action": None,
        "scan": None,
    }
    field = None
    lines = output.splitlines()
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        for name in fields:
            if line.startswith(f"{name}:"):
                fields[name] = line.removeprefix(f"{name}:").strip()
                field = name
                break
        else:
            if field in ("status", "action"):
                assert fields[field] is not None
                fields[field] = f"{fields[field]} {line}"
    return fields


def check_zfs_health(host: str) -> None:
    if not exists_cmd("zpool", host, sudo=True):
        return

    pools = sorted(
        line.strip()
        for line in run_cmd(
            ["zpool", "list", "-H", "-o", "name"], host=host, sudo=True
        ).stdout.splitlines()
        if line.strip()
    )

    for pool in pools:
        res = run_cmd(
            ["zpool", "status", pool],
            host=host,
            sudo=True,
            check=False,
        )
        if res.returncode != 0:
            err = (res.stderr or res.stdout).strip()
            log_msg(f"Unable to retrieve ZFS pool status for {pool}: {err}", host=host)
            continue
        info = parse_zpool_status(res.stdout)

        state = info["state"] or "UNKNOWN"
        log_msg(f"ZFS pool {pool} health: {state}", host=host)

        action_items = []
        action = info["action"]
        if action and action.lower() != "none requested":
            action_items.append(action)

        scan = info["scan"]
        if scan and ("resilver" in scan.lower() or "in progress" in scan.lower()):
            action_items.append(scan)

        if action_items:
            log_msg(
                f"ZFS pool {pool} action items: {'; '.join(action_items)}",
                host=host,
            )


def check_host(host: str) -> None:
    if not exists_cmd("smartctl", host, sudo=True):
        raise UserError("smartctl not found, install smartmontools")
    device_infos = DeviceInfos(host)

    healthy_devices = []
    unhealthy_devices = []
    error_msgs = []

    for device_info in device_infos:
        if device_info.device_type == "disk":
            res = run_cmd(
                [
                    "smartctl",
                    "-H",
                    "--json",
                    device_info.device,
                ],
                host=host,
                sudo=True,
                check=False,
            )
            output = json.loads(res.stdout)
            if res.returncode != 0:
                error_msgs.extend(
                    msg["string"] for msg in output["smartctl"]["messages"]
                )
                continue
            if output["smart_status"]["passed"]:
                healthy_devices.append(device_info.device)
            else:
                unhealthy_devices.append(device_info.device)

    def log_status(devices, status):
        if not devices:
            return
        devices = "\n".join(sorted(map(str, devices)))
        log_msg(f"{status} devices: {devices}", host=host)

    log_status(unhealthy_devices, "Unhealthy")
    log_status(healthy_devices, "Healthy")

    lvm = LVMSetup.from_system(host)
    missing_pvs = "\n".join(sorted(str(pv.device) for pv in lvm.missing_pvs))
    if missing_pvs:
        log_msg(f"Missing PVs (disk failures?): {missing_pvs}", host=host)

    check_zfs_health(host)
