from __future__ import annotations

from typing import NamedTuple

from dnx_gentools.def_constants import TYPE_CHECKING, HOME_DIR, ROOT

from dnx_cli.utils.shell_colors import text
from dnx_cli.utils.io import sexit

if (TYPE_CHECKING):
    from typing import Optional


__all__ = (
    'SERVICE_LIST',

    'COMMANDS', 'MODULES',

    'check_command', 'check_module'
)
if (TYPE_CHECKING):
    __all__.append('Module')


# =========================
# MODULES + HELPERS
# =========================
def check_module(mod: str, /) -> Module:
    module = MODULES.get(mod, None)

    # module level privilege
    if (module.priv_required and not ROOT):
        sexit(
            text.lightgrey(f'Module command "{mod.upper()}" requires ') +
            text.red('root') +
            text.lightgrey(' privileges.')
        )

    return module

class Module(NamedTuple):
    path: Optional[str]
    priv_required: bool
    is_service: bool
    bash_cmd: Optional[str] = None

MODULES = {
    # HELPERS
    'all': Module(path='', priv_required=True, is_service=False),

    # UPDATES
    'system': Module(path='', priv_required=True, is_service=False),
    'signatures': Module(path='', priv_required=True, is_service=False),

    # DB TABLES
    'db-tables': Module(path='dnx_routines.database', priv_required=False, is_service=False),

    # WEBUI
    'webui': Module(path='', priv_required=False, is_service=True),

    # SECURITY MODULES
    'cfirewall': Module(path='dnx_secmods.cfirewall', priv_required=True, is_service=True),
    'dns-proxy': Module(path='dnx_secmods.dns_proxy', priv_required=True, is_service=True),
    'ip-proxy': Module(path='dnx_secmods.ip_proxy', priv_required=True, is_service=True),
    'ids-ips': Module(path='dnx_secmods.ids_ips', priv_required=True, is_service=True),

    # NETWORK MODULES
    'dhcp-server': Module(path='dnx_netmods.dhcp_server', priv_required=True, is_service=True),

    # ROUTINES
    'database': Module(path='dnx_routines.database', priv_required=False, is_service=True),
    'logging': Module(path='dnx_routines.logging', priv_required=False, is_service=True),

    'iptables': Module(path='dnx_iptools.iptables', priv_required=True, is_service=False),

    # SYSTEM
    'startup': Module(path='dnx_control.system.startup_proc', priv_required=True, is_service=True),
    'interface': Module(path='dnx_control.system.interface_services', priv_required=False, is_service=True),
    'syscontrol': Module(path='dnx_control', priv_required=True, is_service=True),

    # COMPILE ONLY
    'dnx-nfqueue': Module(path='1', priv_required=True, is_service=False),
    'cprotocol-tools': Module(path='1', priv_required=True, is_service=False),
    'hash-trie': Module(path='1', priv_required=True, is_service=False),

    # LABEL: DEVELOPMENT_ONLY_CODE
    # TESTS
    'trie-test': Module(path='dnx_profile.utils.unit_tests.trie_test', priv_required=False, is_service=False),
    'webui-dev': Module(
        path=None, bash_cmd=f'bash {HOME_DIR}/dnx_profile/utils/web_run.sh 5001', priv_required=False, is_service=False)
}

SERVICE_LIST = [mod for mod, module in MODULES.items() if module.is_service]

# =========================
# MODULES + HELPERS
# =========================
def check_command(cmd: str, mod: str) -> bool:
    command = COMMANDS.get(cmd, None)
    if (not command):
        sexit(
            text.red('Error! ') +
            text.lightgrey('Unknown Command. -> See help for existing commands')
        )

    # command level privilege
    if (command.priv_required and not ROOT):
        sexit(
            text.lightgrey(f'Command "{cmd.upper()}" requires ') +
            text.red('root') +
            text.lightgrey(' privileges.')
        )

    if (command.module_required and not mod):
        sexit(
            text.red('Error! ') +
            text.lightgrey('Module required for this command. -> See help')
        )

    if (not command.module_required):
        return False

    if (mod not in command.module_list):
        sexit(
            text.red('Error! ') +
            text.lightgrey(f'Module "{mod.upper()}" not available for command "{cmd.upper()}". -> See help')
        )

    return True

class Command(NamedTuple):
    module_required: bool
    priv_required: bool
    module_list: Optional[list[str]] = None
    description: str = ''

COMMANDS: dict[str, Command] = {
    'help': Command(module_required=False, priv_required=False, description='Displays this menu'),

    'start': Command(module_required=True, priv_required=True, module_list=['all', *SERVICE_LIST]),
    'restart': Command(module_required=True, priv_required=True, module_list=['all', *SERVICE_LIST]),
    'stop': Command(module_required=True, priv_required=True, module_list=['all', *SERVICE_LIST]),
    'status': Command(module_required=True, priv_required=True, module_list=['all', *SERVICE_LIST]),
    'journal': Command(module_required=True, priv_required=True, module_list=SERVICE_LIST),

    'cli': Command(module_required=True, priv_required=False, module_list=SERVICE_LIST),

    'install': Command(module_required=False, priv_required=True, module_list=['system']),
    'update': Command(module_required=True, priv_required=True, module_list=['system', 'signatures']),
    'compile': Command(module_required=False, priv_required=True, module_list=['dnx-nfqueue', 'cprotocol-tools', 'hash-trie']),

    'dev': Command(module_required=False, priv_required=False, module_list=['trie-test', 'webui-dev']),

    # deprecated
    'modstat': Command(module_required=False, priv_required=True, description='Deprecated. Use "dnx status all" instead.')
}
