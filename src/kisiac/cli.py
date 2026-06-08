from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser

from kisiac.check import check_host
from kisiac.common import UserError, log_msg
from kisiac.runtime_settings import (
    CheckHostSettings,
    GlobalSettings,
    TestConfigSettings,
    UpdateHostSettings,
)
from kisiac.test_config import test_config
from kisiac.update import setup_config, update_host


def get_argument_parser() -> ArgumentParser:
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    GlobalSettings.register_cli_args(parser)
    subparsers = parser.add_subparsers(dest="subcommand", help="subcommand help")
    update_hosts = subparsers.add_parser(
        "update-hosts",
        help="Update given hosts",
        description="Update given hosts",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    UpdateHostSettings.register_cli_args(update_hosts)
    subparsers.add_parser(
        "setup-config",
        help="Setup the kisiac configuration",
        description="Setup the kisiac configuration",
    )

    check_hosts = subparsers.add_parser(
        "check-hosts",
        help="Check the system healthiness",
        description="Check the system healthiness",
    )
    CheckHostSettings.register_cli_args(check_hosts)

    test_config_parser = subparsers.add_parser(
        "test-config",
        help="Test a kisiac config repo in a container",
        description=(
            "Test a kisiac config repo as if deployed on a real machine, "
            "using a configurable container runtime (docker, podman, apptainer, udocker)."
        ),
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    TestConfigSettings.register_cli_args(test_config_parser)

    return parser


def main() -> None:
    try:
        parser = get_argument_parser()
        args = parser.parse_args()
        GlobalSettings.from_cli_args(args)
        match args.subcommand:
            case "update-hosts":
                UpdateHostSettings.from_cli_args(args)
                for host in UpdateHostSettings.get_instance().hosts:
                    update_host(host)
            case "setup-config":
                setup_config()
            case "check-hosts":
                CheckHostSettings.from_cli_args(args)
                for host in CheckHostSettings.get_instance().hosts:
                    check_host(host)
            case "test-config":
                TestConfigSettings.from_cli_args(args)
                test_config()
            case _:
                parser.print_help()
    except UserError as e:
        log_msg(e)
        exit(1)
