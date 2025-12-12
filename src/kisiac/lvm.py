from collections import defaultdict
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any, Iterable, Self

from humanfriendly import parse_size

from kisiac.common import check_type, exists_cmd, run_cmd


CRYPT_PREFIX = "crypt_"
VGS_DEVICE_REPORT_RE = re.compile(r"^(?P<device>.+)\((?P<info>.+)\)$")


@dataclass(frozen=True)
class PV:
    device: Path


@dataclass(frozen=True)
class LV:
    name: str
    layout: set[str]
    size: int | None
    stripes: int
    stripe_size: int  # in bytes

    def is_same_layout(self, other: Self) -> bool:
        return (
            self.layout <= other.layout
            or other.layout <= self.layout
            and self.stripes == other.stripes
            and self.stripe_size == other.stripe_size
        )

    def is_same_size(self, other: Self) -> bool:
        if self.fills_vg() or other.fills_vg():
            # if both just fill the VG, their sizes are considered unchanged
            return self.fills_vg() and other.fills_vg()

        assert self.size is not None and other.size is not None

        def simplify(size: int) -> int:
            # tens of MB should be precise enough
            return size // 10**7

        return simplify(self.size) == simplify(other.size)

    def fills_vg(self) -> bool:
        return self.size is None

    def size_arg(self) -> list[str]:
        if self.size is None:
            return ["--extents", "+100%FREE"]
        else:
            return ["--size", f"{self.size}B"]

    def stripe_args(self) -> list[str]:
        if self.stripes > 1:
            return [
                "--stripes",
                str(self.stripes),
                "--stripesize",
                f"{self.stripe_size}B",
            ]
        else:
            return []


@dataclass(frozen=True)
class VG:
    name: str
    pvs: set[PV] = field(default_factory=set)
    lvs: dict[str, LV] = field(default_factory=dict)

    def get_lv_device(self, lv_name: str) -> Path:
        return Path("/dev") / self.name / lv_name


@dataclass
class LVMSetup:
    pvs: set[PV] = field(default_factory=set)
    vgs: dict[str, VG] = field(default_factory=dict)
    missing_pvs: set[PV] = field(default_factory=set)

    def is_empty(self) -> bool:
        return not self.pvs and not self.vgs

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> Self:
        check_type("lvm key", config, dict)
        entities = cls()
        for pv in config.get("pvs", []):
            check_type("lvm pv entry", pv, str)
            entities.pvs.add(
                PV(
                    device=Path(pv),
                )
            )
        for name, settings in config.get("vgs", {}).items():
            check_type(f"lvm vg {name} entry", settings, dict)

            lvs = settings.get("lvs", {})
            check_type(f"lvm vg {name} lvs entry", lvs, dict)

            lvs_entities = {}
            for lv_name, lv_settings in lvs.items():
                check_type(f"lvm vg {name} lv {lv_name} entry", lv_settings, dict)

                size = lv_settings["size"]
                if size == "rest":
                    size = None
                else:
                    size = parse_size(size, binary=True)

                lvs_entities[lv_name] = LV(
                    name=lv_name,
                    layout={lv_settings["layout"]},
                    size=size,
                    stripes=lv_settings.get("stripes", 1),
                    stripe_size=parse_size(lv_settings.get("stripe_size", "0B")),
                )

            entities.vgs[name] = VG(
                name=name,
                pvs={PV(device=Path(pv)) for pv in settings.get("pvs", [])},
                lvs=lvs_entities,
            )
        return entities

    @classmethod
    def from_system(cls, host: str) -> Self:
        # check if lvm2 is installed, return empty LVM entities otherwise
        if not exists_cmd("pvcreate", host=host, sudo=True):
            return cls()

        entities: Self = cls()

        lv_data = json.loads(
            run_cmd(
                [
                    "lvs",
                    "--units",
                    "b",
                    "--options",
                    "lv_name,vg_name,lv_layout,lv_size,stripes,stripe_size",
                    "--reportformat",
                    "json",
                ],
                host=host,
                sudo=True,
            ).stdout
        )["report"][0]["lv"]

        vg_devices_raw = json.loads(
            run_cmd(
                ["vgs", "--options", "vg_name,devices", "--reportformat", "json"],
                host=host,
                sudo=True,
            ).stdout
        )["report"][0]["vg"]
        vg_devices = defaultdict(list)
        for entry in vg_devices_raw:
            vg_devices[entry["vg_name"]].append(entry["devices"])

        vg_data = json.loads(
            run_cmd(
                ["vgs", "--options", "vg_name", "--reportformat", "json"],
                host=host,
                sudo=True,
            ).stdout
        )["report"][0]["vg"]

        pv_data = json.loads(
            run_cmd(
                ["pvs", "--options", "pv_name,vg_name", "--reportformat", "json"],
                host=host,
                sudo=True,
            ).stdout
        )["report"][0]["pv"]

        for entry in vg_data:
            vg_name = entry["vg_name"]
            entities.vgs[vg_name] = VG(name=vg_name)

        for vg_name, device_reports in vg_devices.items():
            entities.missing_pvs.update(get_missing_pvs(device_reports))

        for entry in pv_data:
            pv_device = entry["pv_name"]

            pv_obj = PV(device=Path(pv_device))
            entities.pvs.add(pv_obj)
            vg_name = entry["vg_name"]
            if vg_name and vg_name in entities.vgs:
                # in case the PV is assigned to a vg
                entities.vgs[vg_name].pvs.add(pv_obj)

        for entry in lv_data:
            vg = entities.vgs[entry["vg_name"]]
            vg.lvs[entry["lv_name"]] = LV(
                name=entry["lv_name"],
                layout=set(entry["lv_layout"].split(",")),
                size=parse_size(entry["lv_size"], binary=True),
                stripes=entry["stripes"],
                stripe_size=parse_size(entry["stripe_size"]),
            )
        return entities


def get_missing_pvs(device_reports: Iterable[str]) -> Iterable[PV]:
    for device_report in device_reports:
        m = VGS_DEVICE_REPORT_RE.match(device_report)
        assert m is not None, f"Invalid device report: {device_report}"
        info = m.group("info")
        if info == "missing":
            yield PV(device=m.group("device"))
        else:
            try:
                int(info)
            except ValueError:
                raise ValueError(f"Unexpected vgs device info: {info}")
