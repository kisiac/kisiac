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

    @property
    def full_name(self) -> str:
        return f"{self.pool}/{self.name}"


@dataclass(frozen=True)
class ZFSPool:
    name: str
    vdevs: tuple[ZFSVDev, ...]

    def get_create_cmd(self) -> list[str]:
        cmd = ["zpool", "create", "-f", self.name]
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

            setup.pools[pool_name] = ZFSPool(name=pool_name, vdevs=tuple(vdevs))

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

                mountpoint = dataset["mountpoint"]
                check_type(f"mountpoint of {item_msg}", mountpoint, str)

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

    for pool_name, pool in desired.pools.items():
        if pool_name not in existing_pools:
            run_cmd(pool.get_create_cmd(), host=host, sudo=True)

    existing_datasets = set(
        line.strip()
        for line in run_cmd(
            ["zfs", "list", "-H", "-o", "name", "-t", "filesystem"],
            host=host,
            sudo=True,
        ).stdout.splitlines()
        if line.strip()
    )

    password: str | None = None

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
                if password is None:
                    password = provide_password(
                        "Provide ZFS dataset encryption passphrase."
                    )
                run_cmd(
                    create_cmd + [dataset_name],
                    host=host,
                    sudo=True,
                    input=f"{password}\n{password}\n",
                )
            else:
                run_cmd(create_cmd + [dataset_name], host=host, sudo=True)
            continue

        for option in options:
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
