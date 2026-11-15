import re
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum

from kisiac.common import (
    check_type,
    exists_cmd,
    run_cmd,
)
from kisiac.config import Config
from kisiac.runtime_settings import UpdateHostSettings

default_system_software = [
    "openssh-server",
    "openssh-client",
    "lvm2",
    "e2fsprogs",
    "xfsprogs",
    "btrfs-progs",
    "smartmontools",
    "acl",
    "zfsutils-linux",
]


software_spec_re = re.compile(
    r"^(?P<action>(remove|))(?P<system>flatpak|snap|)(?P<pkg>.+)$"
)


class PackageSystem(StrEnum):
    APT = "apt"
    SNAP = "snap"
    FLATPAK = "flatpak"


class PackageAction(StrEnum):
    INSTALL = "install"
    REMOVE = "remove"


@dataclass
class SystemPackage:
    pkg_system: PackageSystem
    name: str
    action: PackageAction


def parse_software_spec(spec: str):
    check_type("software specification", spec, str)
    match = software_spec_re.match(spec)
    if not match:
        raise ValueError(f"Invalid software specification: {spec}")

    action = (
        PackageAction.INSTALL if match.group("action") == "" else PackageAction.REMOVE
    )
    system = match.group("system")
    pkg = match.group("pkg")
    match system:
        case "snap":
            pkg_system = PackageSystem.SNAP
        case "flatpak":
            pkg_system = PackageSystem.FLATPAK
        case _:
            pkg_system = PackageSystem.APT

    return SystemPackage(pkg_system=pkg_system, name=pkg, action=action)


def update_system_packages(host: str) -> None:
    run_cmd(["apt-get", "--yes", "update"], sudo=True, host=host)
    if not UpdateHostSettings.get_instance().skip_system_upgrade:
        run_cmd(["apt-get", "--yes", "upgrade"], sudo=True, host=host)

    software = defaultdict(list)
    software_to_remove = defaultdict(list)
    for spec in set(Config.get_instance().system_software + default_system_software):
        pkg = parse_software_spec(spec)
        if pkg.action == PackageAction.INSTALL:
            software[pkg.pkg_system].append(pkg.name)
        elif pkg.action == PackageAction.REMOVE:
            software_to_remove[pkg.pkg_system].append(pkg.name)

    if pkgs := software.get(PackageSystem.APT):
        run_cmd(
            ["apt-get", "--yes", "install", *pkgs],
            sudo=True,
            host=host,
        )

    if pkgs := software.get(PackageSystem.SNAP):
        if not exists_cmd("snap", host=host, sudo=True):
            run_cmd(["apt-get", "--yes", "install", "snapd"], sudo=True, host=host)
        run_cmd(["snap", "install", pkgs], sudo=True, host=host)

    if pkgs := software.get(PackageSystem.FLATPAK):
        if not exists_cmd("flatpak", host=host, sudo=True):
            run_cmd(["apt-get", "--yes", "install", "flatpak"], sudo=True, host=host)
        run_cmd(["flatpak", "install", "-y", *pkgs], sudo=True, host=host)

    if pkgs := software_to_remove.get(PackageSystem.APT):
        run_cmd(
            ["apt-get", "--yes", "remove", *pkgs],
            sudo=True,
            host=host,
        )

    if pkgs := software_to_remove.get(PackageSystem.SNAP):
        run_cmd(["snap", "remove", *pkgs], sudo=True, host=host)

    if pkgs := software_to_remove.get(PackageSystem.FLATPAK):
        run_cmd(["flatpak", "uninstall", "-y", *pkgs], sudo=True, host=host)
