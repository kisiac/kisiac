from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Self

from kisiac.common import UserError, check_type, run_cmd
from kisiac.filesystems import DeviceInfos


@dataclass(frozen=True)
class Encryption:
    name : str
    device: Path
    hash: str
    cipher: str
    key_size: int

@dataclass
class EncryptionSetup:
    encryptions: set[Encryption]

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> Self:
        check_type("encryption key", config, dict)
        encryptions = set()
        for name, settings in config.items():
            check_type(f"encryption key '{name}'", settings, dict)
            try:
                encryptions.add(
                    Encryption(
                        name=name,
                        device=Path(settings["device"]),
                        hash=settings["hash"],
                        cipher=settings["cipher"],
                        key_size=settings["key_size"],
                    )
                )
            except KeyError as e:
                raise UserError(f"Missing required key '{e.args[0]}' in encryption '{name}'")
        return cls(encryptions=encryptions)

    @classmethod
    def from_system(cls, host: str) -> Self:
        encryptions = set()
        luks_devices = [device for device in DeviceInfos(host) if device.fstype == "crypto_LUKS"]
        for luks_device in luks_devices:
            output = json.loads(run_cmd(["cryptsetup", "luksDump", "--dump-json-metadata", str(luks_device.device)], sudo=True).stdout)
            if len(luks_device.children) != 1:
                raise UserError(
                    f"Unexpected number of children for LUKS device '{luks_device.device}', "
                    "expected exactly 1. This means that your encryption setup is not yet "
                    "supported by kisiac."
                )
            name = luks_device.children[0].device.name
            encryptions.add(Encryption(
                name=name,
                device=luks_device.device,
                hash=output["keyslots"]["0"]["af"]["hash"],
                cipher=output["keyslots"]["0"]["area"]["encryption"],
                key_size=output["keyslots"]["0"]["area"]["key_size"],
            ))
        return cls(encryptions=encryptions)
