import json

from kisiac.common import log_msg, run_cmd
from kisiac.filesystems import DeviceInfos


def check_host(host: str) -> None:
    device_infos = DeviceInfos(host)

    healthy_devices = []
    unhealthy_devices = []

    for device_info in device_infos:
        if device_info.device_type == "disk":
            output = json.loads(
                run_cmd(
                    [
                        "smartctl",
                        "-H",
                        "--json",
                    ],
                    sudo=True,
                ).stdout
            )
            if output["smart_status"]["status"] == "PASSED":
                healthy_devices.append(device_info.device)
            else:
                unhealthy_devices.append(device_info.device)

    def log_status(devices, status):
        devices = "\n".join(sorted(map(str, devices)))
        log_msg(f"{status} devices: {devices}", host=host)

    log_status(unhealthy_devices, "Unhealthy")
    log_status(healthy_devices, "Healthy")
