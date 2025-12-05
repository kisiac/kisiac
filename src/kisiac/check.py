import json

from kisiac.common import log_msg, run_cmd
from kisiac.filesystems import DeviceInfos


def check_host(host: str) -> None:
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
