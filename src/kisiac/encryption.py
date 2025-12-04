from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterator, Self

from kisiac.common import UserError, check_type, run_cmd


@dataclass(frozen=True)
class Encryption:
    name: str | None
    device: Path
    hash: str
    cipher: str
    key_size: int

    def open(self, host: str, password: str) -> None:
        assert self.name is not None
        run_cmd(
            ["cryptsetup", "open", "--key-file", "-", str(self.device), self.name],
            sudo=True,
            input=password,
        )

    def close(self, host: str) -> None:
        assert self.name is not None
        run_cmd(["cryptsetup", "close", self.name], sudo=True)


@dataclass
class EncryptionSetup:
    encryptions: set[Encryption]

    @classmethod
    def from_config(cls, config: list[dict[str, Any]]) -> Self:
        check_type("encryption key", config, list)
        encryptions = set()
        for i, settings in enumerate(config):
            check_type(f"encryption item '{i}'", settings, dict)
            try:
                encryptions.add(
                    Encryption(
                        name=settings.get("name"),
                        device=Path(settings["device"]),
                        hash=settings["hash"],
                        cipher=settings["cipher"],
                        key_size=settings["key_size"],
                    )
                )
            except KeyError as e:
                raise UserError(
                    f"Missing required key '{e.args[0]}' in encryption item '{i}'"
                )
        return cls(encryptions=encryptions)

    @classmethod
    def from_system(cls, host: str) -> Self:
        from kisiac.filesystems import DeviceInfos

        encryptions = set()
        luks_devices = [
            device for device in DeviceInfos(host) if device.fstype == "crypto_LUKS"
        ]
        for luks_device in luks_devices:
            output = json.loads(
                run_cmd(
                    [
                        "cryptsetup",
                        "luksDump",
                        "--dump-json-metadata",
                        str(luks_device.device),
                    ],
                    sudo=True,
                ).stdout
            )
            if len(luks_device.children) > 1:
                raise UserError(
                    f"Unexpected number of children for LUKS device '{luks_device.device}', "
                    "expected at most 1. This means that your encryption setup is not yet "
                    "supported by kisiac."
                )
            name = (
                luks_device.children[0].device.name
                if len(luks_device.children) == 1
                else None
            )
            print(json.dumps(output, indent=2))
            encryptions.add(
                Encryption(
                    name=name,
                    device=luks_device.device,
                    hash=output["keyslots"]["0"]["af"]["hash"],
                    cipher=output["keyslots"]["0"]["area"]["encryption"],
                    key_size=output["keyslots"]["0"]["area"]["key_size"],
                )
            )
        return cls(encryptions=encryptions)

    def by_name(self) -> dict[str, Encryption]:
        return {
            encryption.name: encryption
            for encryption in self.encryptions
            if encryption.name is not None
        }

    def by_device(self) -> dict[Path, Encryption]:
        return {encryption.device: encryption for encryption in self.encryptions}

    def __iter__(self) -> Iterator[Encryption]:
        return iter(self.encryptions)
