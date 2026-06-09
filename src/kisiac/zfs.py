from kisiac.common import confirm_action
from kisiac.common import cmd_to_str
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kisiac.common import UserError, check_type, exists_cmd, provide_password, run_cmd


@dataclass(frozen=True)
class ZFSVDev:
    vdev_type: str
    devices: tuple[Path, ...]


@dataclass(frozen=True)
class ZFSDataset:
    pool: str
    name: str
    mountpoint: Path
    compression: str | None = None
    quota: str | None = None
    reservation: str | None = None
    atime: str | None = None
    encryption: str | None = None
    sync: str | None = None

    @property
    def full_name(self) -> str:
        return f"{self.pool}/{self.name}"


@dataclass(frozen=True)
class ZFSPool:
    name: str
    vdevs: tuple[ZFSVDev, ...]
    ashift: int | None = None

    def get_create_cmd(self) -> list[str]:
        cmd = ["zpool", "create", "-f", self.name]
        if self.ashift is not None:
            cmd.extend(["-o", f"ashift={self.ashift}"])
        spares = []
        for vdev in self.vdevs:
            if vdev.vdev_type == "spare":
                spares.extend(map(str, vdev.devices))
                continue
            cmd.extend([vdev.vdev_type, *map(str, vdev.devices)])
        if spares:
            cmd.extend(["spare", *spares])
        return cmd


@dataclass
class ZFSSetup:
    pools: dict[str, ZFSPool] = field(default_factory=dict)
    datasets: dict[str, ZFSDataset] = field(default_factory=dict)

    # TODO add from_system method to read existing setup and only apply necessary changes
    # also support incremental expansion
    @classmethod
    def from_config(cls, config: list[dict[str, Any]]) -> "ZFSSetup":
        check_type("zfs key", config, list)

        setup = cls()

        for i, pool_settings in enumerate(config):
            check_type(f"zfs item {i}", pool_settings, dict)
            pool_name = pool_settings.get("pool")
            check_type(f"pool name of zfs item {i}", pool_name, str)
            assert isinstance(pool_name, str)

            vdevs_raw = pool_settings.get("vdevs", [])
            check_type(f"vdevs of zfs item {i}", vdevs_raw, list)

            vdevs = []
            for j, vdev in enumerate(vdevs_raw):
                check_type(f"vdev {j} of zfs item {i}", vdev, dict)
                vdev_type = vdev.get("type")
                devices = vdev.get("devices", [])
                check_type(f"vdev type of zfs item {i}, vdev {j}", vdev_type, str)
                check_type(f"devices of zfs item {i}, vdev {j}", devices, list)
                if not devices:
                    raise UserError(f"zfs item {i}, vdev {j} has no devices")
                vdevs.append(
                    ZFSVDev(
                        vdev_type=vdev_type, devices=tuple(Path(d) for d in devices)
                    )
                )

            ashift = pool_settings.get("ashift")
            check_type(f"ashift of zfs item {i}", ashift, (int, type(None)))

            setup.pools[pool_name] = ZFSPool(
                name=pool_name, vdevs=tuple(vdevs), ashift=ashift
            )

            datasets_raw = pool_settings.get("datasets", [])
            check_type(f"datasets of zfs item {i}", datasets_raw, list)
            for j, dataset in enumerate(datasets_raw):
                item_msg = f"zfs item {i}, dataset {j}"
                check_type(f"dataset {item_msg}", dataset, dict)
                ds_name = dataset.get("name")
                check_type(f"dataset name of {item_msg}", ds_name, str)

                atime_entry = dataset.get("atime")
                check_type(
                    f"atime of {item_msg}",
                    atime_entry,
                    (bool, type(None)),
                )
                atime = None if atime_entry is None else "on" if atime_entry else "off"

                sync = dataset.get("sync")
                check_type(
                    f"sync of {item_msg}",
                    sync,
                    (str, type(None)),
                )

                mountpoint = dataset["mountpoint"]
                check_type(f"mountpoint of {item_msg}", mountpoint, str)

                ashift = dataset.get("ashift")
                check_type(f"ashift of {item_msg}", ashift, (int, type(None)))

                def get_option_value(option_name: str) -> str | None:
                    value = dataset.get(option_name)
                    check_type(f"{option_name} of {item_msg}", value, (str, type(None)))
                    return value

                ds = ZFSDataset(
                    pool=pool_name,
                    name=ds_name,
                    mountpoint=Path(mountpoint),
                    compression=get_option_value("compression"),
                    quota=get_option_value("quota"),
                    reservation=get_option_value("reservation"),
                    encryption=get_option_value("encryption"),
                    atime=atime,
                    sync=sync,
                )
                setup.datasets[ds.full_name] = ds

        return setup

    def is_empty(self) -> bool:
        return not self.pools and not self.datasets


def update_zfs(host: str, desired: ZFSSetup) -> None:
    if desired.is_empty():
        return

    if not exists_cmd("zpool", host=host, sudo=True) or not exists_cmd(
        "zfs", host=host, sudo=True
    ):
        raise UserError(
            "ZFS was configured, but zpool/zfs commands are unavailable. Ensure zfsutils-linux is installed."
        )

    existing_pools = set(
        line.strip()
        for line in run_cmd(
            ["zpool", "list", "-H", "-o", "name"], host=host, sudo=True
        ).stdout.splitlines()
        if line.strip()
    )

    cmds = []
    encryption_cmds = []

    for pool_name, pool in desired.pools.items():
        if pool_name not in existing_pools:
            cmds.append(pool.get_create_cmd())

    existing_datasets = set(
        line.strip()
        for line in run_cmd(
            ["zfs", "list", "-H", "-o", "name", "-t", "filesystem"],
            host=host,
            sudo=True,
        ).stdout.splitlines()
        if line.strip()
    )

    for dataset_name, dataset in desired.datasets.items():
        options = ["acltype=posixacl", "xattr=sa"]
        if dataset.mountpoint is not None:
            options.append(f"mountpoint={dataset.mountpoint}")
        if dataset.compression is not None:
            options.append(f"compression={dataset.compression}")
        if dataset.quota is not None:
            options.append(f"quota={dataset.quota}")
        if dataset.reservation is not None:
            options.append(f"reservation={dataset.reservation}")
        if dataset.atime is not None:
            options.append(f"atime={dataset.atime}")
        if dataset.sync is not None:
            options.append(f"sync={dataset.sync}")

        if dataset_name not in existing_datasets:
            create_cmd = [
                "zfs",
                "create",
                *[item for opt in options for item in ["-o", opt]],
            ]
            if dataset.encryption is not None:
                create_cmd.extend(
                    [
                        "-o",
                        f"encryption={dataset.encryption}",
                        "-o",
                        "keyformat=passphrase",
                        "-o",
                        "keylocation=prompt",
                    ]
                )
                encryption_cmds.append(create_cmd + [dataset_name])
            else:
                cmds.append(create_cmd + [dataset_name])
        else:
            for option in options:
                option_name, desired_value = option.split("=", 1)
                actual_value = run_cmd(
                    ["zfs", "get", "-H", "-o", "value", option_name, dataset_name],
                    host=host,
                    sudo=True,
                ).stdout.strip()
                if actual_value != desired_value:
                    run_cmd(["zfs", "set", option, dataset_name], host=host, sudo=True)

            if dataset.encryption is not None:
                actual_encryption = run_cmd(
                    ["zfs", "get", "-H", "-o", "value", "encryption", dataset_name],
                    host=host,
                    sudo=True,
                ).stdout.strip()
                if actual_encryption != dataset.encryption:
                    raise UserError(
                        f"Cannot modify encryption of existing dataset {dataset_name}. "
                        f"Current: {actual_encryption}, desired: {dataset.encryption}"
                    )

                keyformat = run_cmd(
                    ["zfs", "get", "-H", "-o", "value", "keyformat", dataset_name],
                    host=host,
                    sudo=True,
                ).stdout.strip()
                if keyformat != "passphrase":
                    raise UserError(
                        f"Dataset {dataset_name} is encrypted but keyformat is {keyformat}. "
                        "Only passphrase is currently supported."
                    )

    cmd_msg = cmd_to_str(*cmds, *encryption_cmds)

    password = None

    def get_password():
        nonlocal password
        if password is not None:
            return password
        password = provide_password("Provide ZFS dataset encryption passphrase.")
        return password

    if (cmds or encryption_cmds) and confirm_action(
        f"The following ZFS commands will be executed:\n{cmd_msg}\n"
        "\nProceed? If answering no, consider making the changes manually or "
        "adjust the kisiac ZFS configuration."
    ):
        for cmd in cmds:
            run_cmd(
                cmd,
                host=host,
                sudo=True,
                user_error_msg="Incomplete ZFS update due to error (make sure to manually fix this!)",
            )
        if encryption_cmds:
            for cmd in encryption_cmds:
                run_cmd(
                    cmd,
                    host=host,
                    sudo=True,
                    input=f"{get_password()}\n{get_password()}\n",
                    user_error_msg="Incomplete ZFS update due to error (make sure to manually fix this!)",
                )

    # mount datasets that are not yet mounted
    for dataset_name, dataset in desired.datasets.items():
        if dataset.mountpoint is not None:
            # check if dataset is already mounted
            is_mounted = run_cmd(
                ["zfs", "get", "-H", "-o", "value", "mounted", dataset_name],
                host=host,
                sudo=True,
            ).stdout.strip()
            if is_mounted == "yes":
                continue
            # if encrypted dataset, get password and open it first
            if dataset.encryption is not None:
                run_cmd(
                    ["zfs", "load-key", dataset_name],
                    host=host,
                    sudo=True,
                    input=f"{get_password()}\n",
                    user_error_msg=f"Failed to load key for encrypted dataset {dataset_name}.",
                )
            run_cmd(
                ["zfs", "mount", dataset_name],
                host=host,
                sudo=True,
            )
