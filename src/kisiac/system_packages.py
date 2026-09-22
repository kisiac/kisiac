from dataclasses import dataclass
from enum import StrEnum

from src.kisiac.common import check_type


class PackageSystem(StrEnum):
    APT = "apt"
    SNAP = "snap"
    FLATPAK = "flatpak"


@dataclass
class SystemPackage:
    pkg_system: PackageSystem
    name: str


def parse_software_spec(spec: str):
    check_type("software specification", spec, str)
    splitted = spec.split(":")
    if len(splitted) == 2:
        pkg_system = PackageSystem(splitted[0])
        name = splitted[1]
    elif len(splitted) == 1:
        pkg_system = PackageSystem.APT  # default package system if not specified
        name = splitted[0]

    return SystemPackage(pkg_system=pkg_system, name=name)