import sys
from kisiac.common import (
    HostAgnosticPath,
    UserError,
    cmd_to_str,
    confirm_action,
    log_msg,
    multiline_input,
    provide_password,
    run_cmd,
)
from kisiac.encryption import EncryptionSetup
from kisiac.filesystems import DeviceInfos, update_filesystems
from kisiac.runtime_settings import GlobalSettings, UpdateHostSettings
from kisiac import users
from kisiac.config import Config
from kisiac.lvm import LVMSetup


default_system_software = [
    "openssh-server",
    "openssh-client",
    "lvm2",
    "e2fsprogs",
    "xfsprogs",
    "btrfs-progs",
]


def setup_config() -> None:
    if GlobalSettings.get_instance().non_interactive:
        content = sys.stdin.read()
    else:
        content = multiline_input(
            "Paste the initial configuration (YAML format), including the repo key."
        )
    HostAgnosticPath("/etc/kisiac.yaml", sudo=True).write_text(content)


def update_host(host: str) -> None:
    config = Config.get_instance()
    for file in config.files.get_files(user=None):
        log_msg("Updating system file", file.target_path, host=host)
        file.write(overwrite_existing=True, host=host, sudo=True)

    update_system_packages(host)

    update_encryptions(host)

    update_lvm(host)

    update_filesystems(host)

    users.setup_users(host=host)
    for user in config.users:
        for file in config.files.get_files(user.username):
            log_msg("Updating user file", file.target_path, host=host)
            # If the user already has the files, we leave him the new file as a
            # template next to the actual file, with the suffix '.updated'.
            user.fix_permissions(
                file.write(overwrite_existing=False, host=host, sudo=True), host=host
            )


def update_system_packages(host: str) -> None:
    run_cmd(["apt-get", "--yes", "update"], sudo=True, host=host)
    if not UpdateHostSettings.get_instance().skip_system_upgrade:
        run_cmd(["apt-get", "upgrade"], sudo=True, host=host)
    run_cmd(
        ["apt-get", "--yes", "install"]
        + list(set(Config.get_instance().system_software + default_system_software)),
        sudo=True,
        host=host,
    )


def update_encryptions(host: str) -> None:
    desired = Config.get_instance().encryption
    current = EncryptionSetup.from_system(host=host)

    desired_by_name = desired.by_name()
    current_by_device = current.by_device()
    current_by_name = current.by_name()

    for encryption in desired:
        if encryption.name is not None:
            curr_encryption = current_by_name.get(encryption.name)
            if curr_encryption is not None:
                if curr_encryption != encryption:
                    # TODO support such changes
                    raise UserError(
                        f"Encryption {encryption.name} has changed. "
                        "Modifying it via kisiac is not yet supported. "
                        f"Current: {curr_encryption}, Desired: {encryption}"
                    )

    dd_cmds = []
    format_cmds = []

    for encryption in desired:
        if encryption.device not in current_by_device:
            # overwrite the header with random data
            dd_cmds.append(
                [
                    "dd",
                    "if=/dev/urandom",
                    "bs=1M",
                    "count=8",
                    f"of={encryption.device!s}",
                ]
            )
            format_cmds.append(
                [
                    "cryptsetup",
                    "luksFormat",
                    "--cipher",
                    encryption.cipher,
                    "--key-size",
                    encryption.key_size,
                    "--hash",
                    encryption.hash,
                    "--key-file",
                    "-",
                    encryption.device,
                ]
            )

    cmd_msg = cmd_to_str(*(dd_cmds + format_cmds))

    password = None

    def get_password() -> str:
        return provide_password("Provide encryption password.")

    if format_cmds and confirm_action(
        f"The following cryptsetup commands will be executed:\n{cmd_msg}\n"
        "\nProceed? If answering no, consider making the changes manually or "
        "adjust the kisiac encryption configuration."
    ):
        error_msg = "Incomplete encryption update due to error (make sure to manually fix this!)"
        password = get_password()
        for cmd in dd_cmds:
            run_cmd(cmd, host=host, sudo=True, user_error_msg=error_msg)
        for cmd in format_cmds:
            run_cmd(cmd, host=host, sudo=True, user_error_msg=error_msg, input=password)

    encryptions_to_open = [
        encryption for encryption in desired if encryption.name not in current_by_name
    ]
    encryptions_to_reopen = [
        encryption
        for encryption in desired
        if encryption.name in current_by_name
        and current_by_name[encryption.name].device != encryption.device
    ]
    encryptions_to_close = [
        encryption for encryption in current if encryption.name not in desired_by_name
    ]

    if encryptions_to_open or encryptions_to_reopen or encryptions_to_close:
        if password is None:
            password = get_password()

        for encryption in encryptions_to_open:
            encryption.open(host, password)
        for encryption in encryptions_to_reopen:
            encryption.close(host)
            encryption.open(host, password)
        for encryption in encryptions_to_close:
            encryption.close(host)


def update_lvm(host: str) -> None:
    desired = Config.get_instance().lvm
    current = LVMSetup.from_system(host=host)
    device_infos = DeviceInfos(host)

    cmds = []

    cmds.extend(
        [
            "lvremove",
            "--yes",
            f"{vg.name}/{lv}",
        ]
        for vg in current.vgs.values()
        for lv in vg.lvs.values()
        if vg.name not in desired.vgs or lv.name not in desired.vgs[vg.name].lvs
    )
    cmds.extend(
        ["vgremove", "--yes", vg] for vg in current.vgs.keys() - desired.vgs.keys()
    )
    pvremove = [pv.device for pv in current.pvs - desired.pvs]
    if pvremove:
        cmds.append(["pvremove", "--yes", *pvremove])

    pvcreate = [pv.device for pv in desired.pvs - current.pvs]
    if pvcreate:
        cmds.append(["pvcreate", "--yes", *pvcreate])
    cmds.extend(
        ["vgcreate", vg.name] + [pv.device for pv in vg.pvs]
        for vg_name, vg in desired.vgs.items()
        if vg_name not in current.vgs
    )
    cmds.extend(
        [
            "lvcreate",
            "-n",
            lv.name,
            *lv.size_arg(),
            vg.name,
            "--type",
            lv.layout,
        ]
        for vg in desired.vgs.values()
        for lv in vg.lvs.values()
        if vg.name not in current.vgs or lv.name not in current.vgs[vg.name].lvs
    )

    # update existing VGs and LVs
    for vg_desired in desired.vgs.values():
        vg_current = current.vgs.get(vg_desired.name)
        if vg_current is None:
            continue

        # update pvs in vg
        pvs_to_add = vg_desired.pvs - vg_current.pvs
        if pvs_to_add:
            cmds.append(
                ["vgextend", vg_desired.name] + [pv.device for pv in pvs_to_add]
            )
        pvs_to_remove = vg_current.pvs - vg_desired.pvs
        if pvs_to_remove:
            cmds.append(
                ["vgreduce", "--yes", vg_desired.name]
                + [pv.device for pv in pvs_to_remove]
            )

        # update lvs in vg
        for lv_desired in vg_desired.lvs.values():
            lv_current = vg_current.lvs.get(lv_desired.name)
            if lv_current is None:
                continue
            if lv_current.layout != lv_desired.layout:
                raise UserError(
                    f"Cannot change layout of existing LV {lv_desired.name} "
                    f"from {lv_current.layout} to {lv_desired.layout}. "
                    "Perform this action manually and re-run the update."
                )

            if not lv_current.is_same_size(lv_desired):
                if lv_desired.fills_vg():
                    log_msg(f"Ensuring that LV {lv_desired.name} fills VG.", host=host)
                else:
                    log_msg(
                        f"Resizing LV {lv_desired.name} from {lv_current.size} to "
                        f"{lv_desired.size}",
                        host=host,
                    )

                device_info = device_infos.get_info_for_device(
                    vg_desired.get_lv_device(lv_desired.name)
                )
                resize_fs = ["--resizefs"] if device_info.fs_type is not None else []

                cmds.append(
                    [
                        "lvresize",
                        *resize_fs,
                        *lv_desired.size_arg(),
                        f"{vg_desired.name}/{lv_desired.name}",
                    ]
                )
    cmd_msg = cmd_to_str(*cmds)

    if confirm_action(
        f"The following LVM commands will be executed:\n{cmd_msg}\n"
        "\nProceed? If answering no, consider making the changes manually or "
        "adjust the kisiac LVM configuration."
    ):
        for cmd in cmds:
            run_cmd(
                cmd,
                host=host,
                sudo=True,
                user_error_msg="Incomplete LVM update due to error (make sure to manually fix this!)",
            )
