from types import SimpleNamespace

from kisiac import system_packages


def test_flatpak_installs_register_flathub_remote(monkeypatch) -> None:
    commands = []
    monkeypatch.setattr(
        system_packages.Config,
        "get_instance",
        lambda: SimpleNamespace(system_software=["flatpak:org.gnome.Calculator"]),
    )
    monkeypatch.setattr(
        system_packages.UpdateHostSettings,
        "get_instance",
        lambda: SimpleNamespace(skip_system_upgrade=True),
    )
    monkeypatch.setattr(
        system_packages,
        "exists_cmd",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        system_packages,
        "run_cmd",
        lambda cmd, **_kwargs: commands.append(cmd),
    )

    system_packages.update_system_packages("localhost")

    remote_add = [
        "flatpak",
        "remote-add",
        "--if-not-exists",
        "flathub",
        "https://dl.flathub.org/repo/flathub.flatpakrepo",
    ]
    install = ["flatpak", "install", "-y", "org.gnome.Calculator"]
    assert remote_add in commands
    assert commands.index(remote_add) < commands.index(install)
