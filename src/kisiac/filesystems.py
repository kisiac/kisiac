from copy import copy
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import subprocess as sp
from typing import Any, Iterator, Self
from kisiac.common import HostAgnosticPath, UserError, confirm_action, run_cmd
from kisiac.config import Config, Filesystem, UserSet

from pyfstab import Fstab

blkid_attrs_re = re.compile(r'(?P<attr>[A-Z]+)="(?P<value>\S+)"')


def update_filesystems(host: str) -> None:
    filesystems = set(Config.get_instance().filesystems)
    device_infos = DeviceInfos(host)

    # First, create filesystems that do not exist yet or need to be changed.
    mkfs_cmds = []
    for filesystem in filesystems:
        device_info = device_infos.get_info(filesystem)
        if device_info.fs_type != filesystem.fs_type:
            mkfs_cmds.append(
                ["mkfs", "-t", filesystem.fs_type, str(device_info.device)]
            )

    # Second, update /etc/fstab.
    fstab_path = HostAgnosticPath("/etc/fstab", host=host, sudo=True)
    old_fstab = Fstab().read_string(fstab_path.read_text())

    mkfs_cmds_msg = "\n".join(" ".join(cmd) for cmd in mkfs_cmds)

    new_fstab = Fstab()
    new_fstab.entries = [
        filesystem.to_fstab_entry() for filesystem in sorted(filesystems)
    ]

    if mkfs_cmds and confirm_action(
        f"The following mkfs commands will be executed:\n{mkfs_cmds_msg}"
    ):
        for cmd in mkfs_cmds:
            run_cmd(cmd, sudo=True, host=host)

    if str(new_fstab) != str(old_fstab) and confirm_action(
        f"\nThe following will be the new fstab:\n{new_fstab.write_string()}"
    ):
        new_fstab = Fstab()
        new_fstab.entries = [
            filesystem.to_fstab_entry() for filesystem in sorted(filesystems)
        ]
        fstab_path.write_text(new_fstab.write_string())

    for filesystem in filesystems:
        if filesystem.mountpoint is not None:
            run_cmd(["mkdir", "-p", filesystem.mountpoint], host=host, sudo=True)
            try:
                run_cmd(
                    ["mount", filesystem.mountpoint],
                    host=host,
                    sudo=True,
                    user_error=False,
                )
            except sp.CalledProcessError as e:
                # returncode 5 means that the item is already mounted
                if e.returncode != 5:
                    raise


def update_permissions(host: str) -> None:
    def apply_user_set(user_set: UserSet | None, flag: str) -> list[str]:
        if user_set is None:
            return []
        if user_set == UserSet.owner:
            return [f"u+{flag}", f"g-{flag}", f"o-{flag}"]
        elif user_set == UserSet.group:
            return [f"u+{flag}", f"g+{flag}", f"o-{flag}"]
        elif user_set == UserSet.others:
            return [f"u+{flag}", f"g+{flag}", f"o+{flag}"]
        elif user_set == UserSet.nobody:
            return [f"u-{flag}", f"g-{flag}", f"o-{flag}"]
        else:
            assert False, "unreachable"

    permissions = Config.get_instance().permissions
    for path, permissions in permissions.items():
        path = HostAgnosticPath(path, host=host, sudo=True)
        chmod_args = []
        if permissions.setgid:
            chmod_args.append("g+s")
        if permissions.setuid:
            chmod_args.append("u+s")
        if permissions.sticky:
            chmod_args.append("+t")
        chmod_args.extend(apply_user_set(permissions.read, "r"))
        chmod_args.extend(apply_user_set(permissions.write, "w"))
        if chmod_args:
            path.chmod(*chmod_args)

        # execute permissions are handled differently for dir and files
        if path.is_dir():
            if permissions.read is not None:
                # With dirs, read should be considered equivalent to execute, and handled
                # non-recursively. In turn, we ignore the execute setting for dirs because
                # it becomes redundant.
                path.chmod(*apply_user_set(permissions.read, "x"), recursive=False)
        elif permissions.execute is not None:
            path.chmod(*apply_user_set(permissions.execute, "x"))
        path.chown(permissions.owner, permissions.group)


@dataclass
class DeviceInfo:
    device: Path
    device_type: str
    fs_type: str | None
    label: str | None
    uuid: str | None
    children: list[Self] = field(default_factory=list)

    def with_device(self, device: Path) -> Self:
        info = copy(self)
        info.device = device
        return info


class DeviceInfos:
    def __init__(self, host: str) -> None:
        self.infos: list[DeviceInfo] = []
        self.host = host
        self._from_system(update=True)

    def _from_system(
        self, update: bool, device: Path | None = None
    ) -> DeviceInfo | None:
        typo_hint = "Typo in the device name?" if device else ""
        lsblk_output = json.loads(
            run_cmd(
                [
                    "lsblk",
                    "--json",
                    "--paths",
                    "--output",
                    "NAME,FSTYPE,LABEL,UUID,TYPE",
                    *([device] if device else []),
                ],
                sudo=True,
                host=self.host,
                user_error_msg=f"Unable to retrieve device info.{typo_hint}",
            ).stdout
        )

        def parse_entry(entry: dict[str, Any]) -> DeviceInfo:
            reported_device = Path(entry["name"])
            device_info = DeviceInfo(
                device=reported_device,
                device_type=entry["type"],
                fs_type=entry["fstype"],
                label=entry["label"],
                uuid=entry["uuid"],
            )
            if update:
                self.infos.append(device_info)
                if reported_device.is_relative_to(Path("/dev/mapper")):
                    # also add /dev/vgname/lvname path for LVM logical volumes
                    reported_device = Path("/dev") / re.sub(
                        r"(?P<pre>[^-])-(?P<post>[^-])",
                        r"\g<pre>/\g<post>",
                        reported_device.name,
                        count=1,
                    ).replace("--", "-")
                    self.infos.append(device_info.with_device(Path(reported_device)))

            for child in entry.get("children", []):
                device_info.children.append(parse_entry(child))
            return device_info

        device_info = None
        for entry in lsblk_output["blockdevices"]:
            device_info = parse_entry(entry)

        if device is not None:
            assert device_info is not None
            return device_info

    def get_info(self, filesystem: Filesystem) -> DeviceInfo:
        def is_targeted_by_filesystem(device_info: DeviceInfo) -> bool:
            if filesystem.label is not None:
                return device_info.label == filesystem.label
            elif filesystem.uuid is not None:
                return device_info.uuid == filesystem.uuid
            else:
                return False

        if filesystem.device is not None:
            return self.get_info_for_device(filesystem.device)

        for info in self.infos:
            if is_targeted_by_filesystem(info):
                return info

        raise UserError(
            f"No device found for filesystem with device={filesystem.device}, "
            f"label={filesystem.label}, uuid={filesystem.uuid}"
        )

    def get_info_for_device(self, device: Path) -> DeviceInfo:
        def find_device() -> DeviceInfo | None:
            for info in self.infos:
                if info.device == device:
                    return info

        found_device = find_device()
        if found_device is None:
            found_device = self._from_system(update=False, device=device)
            assert found_device is not None
            return found_device

        return found_device

    def __iter__(self) -> Iterator[DeviceInfo]:
        return iter(self.infos)
