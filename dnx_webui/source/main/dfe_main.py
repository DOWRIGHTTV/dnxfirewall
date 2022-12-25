#!/usr/bin/env python3

from __future__ import annotations

import os
from datetime import timedelta

from source.web_typing import *

from dnx_gentools.def_constants import HOME_DIR, FIVE_SEC, ppt
from dnx_gentools.def_enums import CFG
from dnx_gentools.def_exceptions import ConfigurationError
from dnx_gentools.file_operations import load_configuration, ConfigurationManager

from dnx_iptools.cprotocol_tools.cprotocol_tools import itoip

from dnx_routines.database.ddb_connector_sqlite import DBConnector
from dnx_routines.logging.log_client import LogHandler as Log

import source.web_validate as validate

# ========================================
# FLASK API - APP INSTANCE INITIALIZATION
# ========================================
from flask import Flask, jsonify, redirect, render_template, request, session, url_for, g as context_global

app = Flask(
    __name__, static_folder=f'{HOME_DIR}/dnx_webui/static', template_folder=f'{HOME_DIR}/dnx_webui/templates'
)

# easy access to app instance by outer components
Flask.app = app

# a new key is generated on every system start and stored in system config.
app_config: ConfigChain = load_configuration('system', cfg_type='global')
app.secret_key = app_config['flask->key']

app.jinja_env.trim_blocks   = True
app.jinja_env.lstrip_blocks = True

# =========================================
# DNX API - LOGGING / FIREWALL / CONFIG
# =========================================
from dnx_control.control.ctl_action import system_action
from dnx_secmods.cfirewall.fw_control import FirewallControl

general_error_page = 'main/general_error.html'
application_error_page = 'main/application_error.html'

# setup for system logging
Log.run(name='web_app')

# NOTE: this will allow the config manager to reference the Log class without an import. (cyclical import error)
ConfigurationManager.set_log_reference(Log)

# initialize cfirewall manager, which interfaces with cfirewall control class through a fd.
cfirewall = FirewallControl()

# setting FirewallManager instance as class var within FirewallManager to access instance throughout webui
FirewallControl.cfirewall = cfirewall

# =========================================
# WEBUI COMPONENTS
# =========================================
import source.main.dfe_dashboard as dfe_dashboard
from source.rules.dfe_firewall import WebPage as dnx_fwall  # non standard -> firewall page logic
from source.rules.dfe_nat import WebPage as dnx_nat
from source.intrusion.dfe_ip import WebPage as ip_proxy
from source.intrusion.domain.dfe_domain import WebPage as dns_proxy
from source.intrusion.domain.dfe_xlist import WebPage as xlist
from source.intrusion.domain.dfe_categories import WebPage as category_settings
from source.intrusion.dfe_ids_ips import WebPage as dnx_ips
from source.system.settings.dfe_dns import WebPage as dns_settings
from source.system.settings.dfe_dhcp import WebPage as dhcp_settings
from source.system.settings.dfe_interface import WebPage as interface_settings
from source.system.settings.dfe_logging import WebPage as logging_settings
# import source.system.settings.dfe_syslog as syslog_settings
from source.system.log.dfe_traffic import WebPage as traffic_logs  # non standard -> log page logic
from source.system.log.dfe_events import WebPage as sec_events  # non standard -> log page logic
from source.system.log.dfe_system import WebPage as sys_logs  # non standard -> log page logic
from source.system.dfe_users import WebPage as dfe_users
from source.system.dfe_backups import WebPage as dfe_backups
from source.system.dfe_services import WebPage as dnx_services

from source.main.dfe_authentication import *

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING
if (TYPE_CHECKING):
    from source.web_typing import Optional, Union, ConfigChain

# --------------------------------------------- #
#  START OF NAVIGATION TABS
# --------------------------------------------- #
# TODO: figure out best visually pleasing way to inject current logged in user info on each page.
@app.route('/dashboard', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def dnx_dashboard(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['dashboard'])

    page_settings['dashboard'] = dfe_dashboard.load_page()
    page_settings['footer'] = True

    return render_template('main/dashboard.html', theme=context_global.theme, **page_settings)

# --------------------------------------------- #
#  START OF RULES TAB
# --------------------------------------------- #
@app.route('/rules/firewall', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_firewall(session_info: dict):

    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'ajax': True, 'dnx_table': True, 'auto_colorize': True,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'dnx_network_objects': {},
        'dnx_service_objects': {},
        'selected': 'MAIN',
        'sections': ['BEFORE', 'MAIN', 'AFTER'],
        'uri_path': ['rules', 'firewall']
    }

    page_settings.update(session_info)

    page_action = firewall_page_logic(
        dnx_fwall, page_settings, 'firewall_settings', page_name='rules/firewall/firewall.html'
    )

    return page_action

@app.route('/rules/firewall/commit', methods=['POST'])
@user_restrict('admin')
def rules_firewall_commit(session_info: dict):

    # TODO: get user and ip information so we can log the commit (warning?)

    json_data = request.get_json(force=True)

    status, err_data = dnx_fwall.handle_ajax(json_data)

    return ajax_response(status=status, data=err_data)

@app.route('/rules/firewall/push', methods=['POST'])
@user_restrict('admin')
def rules_firewall_push(session_info: dict):
    # for when we implement preview option
    # json_data = request.get_json(force=True)

    if error := FirewallControl.push():
        return ajax_response(status=False, data={'error': 1, 'message': 'push failed'})

    return ajax_response(status=True, data={'error': 0, 'message': 'push success'})

@app.route('/rules/nat', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_nat(session_info: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'menu': validate.get_convert_int(request.args, 'menu'),
        'selected': 'WAN_ZONE',
        'zones': ['WAN', 'DMZ', 'LAN'],
        'uri_path': ['rules', 'nat']
    }

    page_settings.update(session_info)

    page_action = firewall_page_logic(
        dnx_nat, page_settings, 'nat_settings', page_name='rules/nat.html'
    )

    return page_action

# --------------------------------------------- #
#  START OF INTRUSION TAB
# --------------------------------------------- #
@app.route('/intrusion/ip', methods=['GET', 'POST'])
@user_restrict('admin')
def intrusion_ip(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['intrusion', 'ip'])

    page_settings['ajax'] = True

    page_action = standard_page_logic(
        ip_proxy, page_settings, 'ip_settings', page_name='intrusion/ip.html'
    )

    return page_action

# TODO: work on proper response
@app.post('/intrusion/ip/post')
@user_restrict('admin')
def intrusion_ip_post(session_info: dict):

    json_data = request.get_json(force=True)

    status, err_data = ip_proxy.handle_ajax(json_data)

    # print(f'[commit/response] status={status}, err_data={err_data}')

    return ajax_response(status=status, data=err_data)

@app.route('/intrusion/domain', methods=['GET', 'POST'])
@user_restrict('admin')
def intrusion_domain(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['intrusion', 'domain'])

    page_settings['ajax'] = True

    page_action = standard_page_logic(
        dns_proxy, page_settings, 'domain_settings', page_name='intrusion/domain/domain.html'
    )

    return page_action

@app.post('/intrusion/domain/post')
@user_restrict('admin')
def intrusion_domain_post(session_info: dict):

    json_data = request.get_json(force=True)

    status, err_data = dns_proxy.handle_ajax(json_data)

    # print(f'[commit/response] status={status}, err_data={err_data}')

    return ajax_response(status=status, data=err_data)

    #  START OF DOMAIN SUB MENU
    # ----------------------------------------- #
@app.route('/intrusion/domain/whitelist', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_overrides_whitelist(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['intrusion', 'domain', 'whitelist'])

    page_action = standard_page_logic(
        xlist, page_settings, 'whitelist_settings', page_name='intrusion/domain/whitelist.html'
    )

    return page_action

@app.route('/intrusion/domain/blacklist', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_overrides_blacklist(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['intrusion', 'domain', 'blacklist'])

    page_action = standard_page_logic(
        xlist, page_settings, 'blacklist_settings', page_name='intrusion/domain/blacklist.html'
    )

    return page_action

@app.route('/intrusion/domain/categories', methods=['GET', 'POST'])
@user_restrict('admin')
def intrusion_domain_categories(session_info: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'menu': validate.get_convert_int(request.args, 'menu'),
        'cat_settings': True,
        'uri_path': ['intrusion', 'domain', 'categories']
    }

    page_settings.update(session_info)

    page_action = categories_page_logic(category_settings, page_settings)

    return page_action

    #  END OF DOMAIN SUB MENU
    # ----------------------------------------- #
@app.route('/intrusion/ips', methods=['GET', 'POST'])
@user_restrict('admin')
def intrusion_ips(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['intrusion', 'ips'])

    page_action = standard_page_logic(
        dnx_ips, page_settings, 'ips_settings', page_name='intrusion/ips.html'
    )

    return page_action

# --------------------------------------------- #
#  START OF SYSTEMS MENU
# --------------------------------------------- #
    #  START OF SETTINGS SUB MENU
    # ----------------------------------------- #
@app.route('/system/settings/dns', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_dns(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['system', 'settings', 'dns'])

    page_action = standard_page_logic(
        dns_settings, page_settings, 'dns_settings', page_name='system/settings/dns.html'
    )

    return page_action

@app.route('/system/settings/dhcp', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_dhcp(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['system', 'settings', 'dhcp'])

    page_action = standard_page_logic(
        dhcp_settings, page_settings, 'dhcp_settings', page_name='system/settings/dhcp.html'
    )

    return page_action

@app.route('/system/settings/interface', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_interface(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['system', 'settings', 'interface'])

    page_action = standard_page_logic(
        interface_settings, page_settings, 'interface_settings', page_name='system/settings/interface.html'
    )

    return page_action

@app.route('/system/settings/logging', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_logging(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['system', 'settings', 'logging'])

    page_action = standard_page_logic(
        logging_settings, page_settings, 'logging_settings', page_name='system/settings/logging.html'
    )

    return page_action

# NOTE: syslog module out of spec and needs to be reworked.
# priority is lower than other implementations.
# @app.route('/system/settings/syslog', methods=['GET', 'POST'])
# @user_restrict('admin')
# def system_settings_syslog(session_info: dict):
#     page_settings = {
#         'navi': True, 'idle_timeout': True, 'standard_error': None,
#         'tab': validate.get_convert_int(request.args, 'tab'),
#         'uri_path': ['system', 'settings', 'syslog']
#     }
#
#     page_settings.update(session_info)
#
#     page_action = standard_page_logic(
#         syslog_settings, page_settings, 'syslog_settings', page_name='system/settings/syslog.html'
#     )
#
#     return page_action

    # END OF SETTINGS SUB MENU
    # ----------------------------------------- #
@app.route('/system/log/traffic', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_logs_traffic(session_info: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'table': '1', 'dnx_table': True, 'ajax': False, 'auto_colorize': True,
        'table_types': ['firewall', '.nat'],
        'uri_path': ['system', 'log', 'traffic']
    }

    page_settings.update(session_info)

    page_action = log_page_logic(traffic_logs, page_settings, page_name='system/log/traffic/traffic.html')

    return page_action

@app.route('/system/log/events', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_logs_traffic_events(session_info: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'table': '1', 'dnx_table': True, 'ajax': False, 'auto_colorize': True,
        'table_types': ['dns_proxy', 'ip_proxy', 'intrusion_prevention', 'infected_clients'],
        'uri_path': ['system', 'log', 'events']
    }

    page_settings.update(session_info)

    page_action = log_page_logic(sec_events, page_settings, page_name='system/log/events/events.html')

    return page_action

@app.route('/system/log/system', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_logs_system(session_info: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'dnx_table': True, 'ajax': True, 'auto_colorize': True,
        'log_files': [
            'combined', 'logins', 'web_app', 'system', 'dns_proxy', 'ip_proxy', 'ips', 'dhcp_server',  # 'syslog'
        ],
        'uri_path': ['system', 'log', 'system']
    }

    page_settings.update(session_info)

    page_action = log_page_logic(sys_logs, page_settings, page_name='system/log/system/system.html')

    return page_action

@app.post('/system/log/system/get')
@user_restrict('user', 'admin')
def system_logs_get(session_info: dict):
    json_data = request.get_json(force=True)

    _, _, table_data = sys_logs.handle_ajax(json_data)

    return ajax_response(status=True, data=table_data)

@app.route('/system/users', methods=['GET', 'POST'])
@user_restrict('admin')
def system_users(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['system', 'users'])

    page_action = standard_page_logic(
        dfe_users, page_settings, 'user_list', page_name='system/users.html'
    )

    return page_action

@app.route('/system/backups', methods=['GET', 'POST'])
@user_restrict('admin')
def system_backups(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['system', 'backups'])

    page_action = standard_page_logic(
        dfe_backups, page_settings, 'current_backups', page_name='system/backups.html')

    return page_action

@app.route('/system/services', methods=['GET', 'POST'])
@user_restrict('admin')
def system_services(session_info: dict):
    page_settings = get_default_page_settings(session_info, uri_path=['system', 'services'])

    page_action = standard_page_logic(
        dnx_services, page_settings, 'service_info', page_name='system/services.html')

    return page_action

# --------------------------------------------- #
#  START OF DEVICE MENU
# --------------------------------------------- #
@app.route('/device/<path>', methods=['GET', 'POST'])
@user_restrict('admin')
def system_restart(session_info: dict, path: str):
    if (path not in ['shutdown', 'restart']):
        return render_template(general_error_page, general_error=f'device/{path} not found.')

    page_settings = get_default_page_settings(session_info, uri_path=['device', path])

    page_settings['idle_timeout'] = False
    page_settings['control'] = True
    page_settings['action'] = path

    return handle_system_action(page_settings)

# --------------------------------------------- #
#  START OF LOGOUT MENU
# --------------------------------------------- #
@app.get('/logout')
@user_restrict('user', 'admin')
# removing user from session dict then removing them from locally stored session tracker to allow for cross session
# awareness of users/accounts logged in.
def dnx_logout(session_info: dict):
    if user := session.pop('user', None):
        update_session_tracker(user, action=CFG.DEL)

    return redirect(url_for('dnx_login'))


@app.route('/login', methods=['GET', 'POST'])
# TODO: consider dropping flask session outright since it is redundant to dnx session tracker.
#  make sure its not needed for the auto session timeout first though...
def dnx_login():
    # the user has an active authenticated session, so we can drop them back to the dashboard.
    if (session.get('user', None)):
        return redirect(url_for('dnx_dashboard'))

    page_settings = {
        'navi': False, 'login_btn': False, 'idle_timeout': False,
        'standard_error': False, 'login_error': '',
        'uri_path': ['login']
    }

    if (request.method == 'POST'):

        authenticated, username, user_role = Authentication.user_login()
        if (authenticated):
            return redirect(url_for('dnx_dashboard'))

        page_settings['login_error'] = 'Invalid Credentials. Please try again.'

    return render_template('main/login.html', theme=context_global.theme, **page_settings)

# --------------------------------------------- #
#  BLOCKED PAGE | dns redirect
# --------------------------------------------- #
@app.route('/blocked')
def dnx_blocked() -> str:
    page_settings = {
        'navi': False, 'login_btn': True, 'idle_timeout': False,
        'uri_path': ['blocked']
    }

    # checking for domain sent by nginx that is being redirected.
    # if a domain block event is not associated with the request (user navigated to this page manually) then a not
    #  authorized page will be served.
    # If the domain is not valid (regex) then the request will be redirected back to the blocked page without a domain.
    # NOTE: this is a crazy bit of code that should be tested much more as it is possible to do a sql injection here
    #  if the validations below are bypassed.
    blocked_domain = request.args.get('dom', None)
    if (not blocked_domain):
        session.pop('user', None)

        return render_template('main/not_authorized.html', theme=context_global.theme, **page_settings)

    try:
        validate.domain_name(blocked_domain)
    except validate.ValidationError:
        session.pop('user', None)

        return render_template('main/not_authorized.html', theme=context_global.theme, **page_settings)

    with DBConnector() as firewall_db:
        domain_info = firewall_db.execute('blocked_domain', domain=blocked_domain, src_ip=request.remote_addr)

    if (not domain_info):
        session.pop('user', None)

        return render_template('main/not_authorized.html', theme=context_global.theme, **page_settings)

    page_settings.update({
        'navi': True,
        'standard_error': False,
        'src_ip': request.remote_addr,
        'blocked': domain_info})

    return render_template('main/blocked.html', theme=context_global.theme, **page_settings)

# --------------------------------------------- #
# --------------------------------------------- #

@app.post('/refresh/session')
@user_restrict('user', 'admin')
def refresh_session(session_info: dict):

    return ajax_response(status=True, data={'error': 0, 'message': None})

# --------------------------------------------- #
# --------------------------------------------- #
@app.get('/')
def main():
    return send_to_login_page()

# TODO: make this use a new non application error page because explanation doesnt make sense. also transfer session
#  of logged in users.
@app.errorhandler(404)
def page_not_found(error):

    return render_template(general_error_page, theme=context_global.theme, general_error='page not found.')

# --------------------------------------------- #
# all standard page loads use this logic to decide the page action/ call the correct
# lower level functions residing in each page's module
def standard_page_logic(dnx_page: StandardWebPage, page_settings: dict, data_key: str, *, page_name: str) -> str:

    if (request.method == 'POST'):
        try:
            error, err_msg = dnx_page.update(request.form)
        except ConfigurationError as ce:
            return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

        std_error = f'{err_msg} code={error}' if err_msg else ''

        page_settings.update({
            'tab': validate.get_convert_int(request.form, 'tab'),
            'standard_error': std_error
        })

    try:
        page_settings[data_key] = dnx_page.load(request.form)
    except ConfigurationError as ce:
        return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

    return render_template(page_name, theme=context_global.theme, **page_settings)

def firewall_page_logic(dnx_page: RulesWebPage, page_settings: dict, data_key: str, *, page_name: str) -> str:

    if (request.method == 'POST'):
        try:
            error, selected = dnx_page.update(request.form)
        except ConfigurationError as ce:
            return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

        page_settings.update({
            'tab': validate.get_convert_int(request.form, 'tab'),
            'selected': selected,
            'standard_error': error
        })

    try:
        page_settings[data_key] = dnx_page.load(page_settings['selected'])
    except ConfigurationError as ce:
        return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

    return render_template(page_name, theme=context_global.theme, **page_settings)

def log_page_logic(log_page: LogWebPage, page_settings: dict, *, page_name: str) -> str:
    # can now accept redirects from other places on the webui to load specific tables directly on load
    # using uri queries FIXME: this has been temporarily suspended and should be reintroduced.

    # TODO: we dont have explicit logic for "GET" and rely on exception handling to load page via GET. fix???

    try:
        table, menu, table_data = log_page.update(request.form)
    except ConfigurationError as ce:
        return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

    page_settings.update({
        'table': table,
        'menu': menu,
        'table_data': table_data
    })

    return render_template(page_name, theme=context_global.theme, **page_settings)

def categories_page_logic(dnx_page, page_settings: dict) -> str:
    if (request.method == 'POST'):
        try:
            error, menu_option = dnx_page.update(request.form)
        except ConfigurationError as ce:
            return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

        page_settings.update({
            'tab': validate.get_convert_int(request.args, 'tab'),
            'menu': validate.get_convert_int(request.args, 'menu'),
            'standard_error': error
        })

    try:
        page_settings['category_settings'] = dnx_page.load(page_settings['menu'])
    except ConfigurationError as ce:
        return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

    return render_template('intrusion/domain/categories.html', theme=context_global.theme, **page_settings)

# function called by restart/shutdown pages. will ensure the user specified operation gets executed
def handle_system_action(page_settings: dict):
    action = page_settings['action']

    response = request.form.get(f'system_{action}', '')
    if (not response):
        return render_template(application_error_page, application_error='device action invalid.', theme=context_global.theme, **page_settings)

    if (response == 'YES'):
        page_settings.pop('control', None)
        page_settings.pop('user_role', None)
        page_settings.update({
            'confirmed': True,
            'login_btn': True
        })

        Log.warning(f'dnxfirewall {action} initiated.')

        # I prefer the word restart, so converting to system command here
        action = 'reboot' if action == 'restart' else f'{action} now'

        # TODO: make sure this is authenticated
        # forwarding request to system control service via local socket for execution
        system_action(delay=FIVE_SEC, module='webui', command=action)

    elif (response == 'NO'):
        return redirect(url_for('dnx_dashboard'))

    return render_template('main/device.html', theme=context_global.theme, **page_settings)

# =================================
# HELPERS
# =================================
def get_default_page_settings(session_info, *, uri_path: list[str]) -> dict:
    '''sets the following values:

        - navi->True
        - idle_timeout->True
        - standard_error->None
        - tab from request args "?tab".

    page_settings will be updated with passed in session data.
    '''
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': uri_path
    }

    page_settings.update(session_info)

    return page_settings

def ajax_response(*, status: bool, data: Union[dict, list]):
    if (not isinstance(status, bool)):
        raise TypeError('Ajax response status must be a boolean.')

    # print(jsonify({'success': status, 'result': data}))

    return jsonify({'success': status, 'result': data})

# =================================
# FLASK API - REQUEST MODS
# =================================
@app.before_request
def user_timeout() -> None:
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

@app.before_request
def set_user_settings() -> None:
    if not (user := authenticated_session()): return

    # ------------------
    # WEBUI THEME
    # ------------------
    if new_theme := request.args.get('theme'):

        if new_theme not in ['light', 'dark']: return

        with ConfigurationManager('logins', file_path='/dnx_webui/data') as webui:
            webui_settings: ConfigChain = webui.load_configuration()

            # this check prevents issues with log in/out transitions
            if user in webui_settings.get_list('users'):

                webui_settings[f'users->{user}->settings->theme'] = new_theme

                webui.write_configuration(webui_settings.expanded_user_data)

@app.before_request
def load_user_settings() -> None:

    # loading defaults before returning. manually setting since theme is only tracked setting as of now.
    if not (user := authenticated_session()):
        context_global.settings = {'theme': 'light'}

    else:
        # 1. theme
        web_config: ConfigChain = load_configuration('logins', filepath='/dnx_webui/data')

        context_global.settings = web_config.get_dict(f'users->{user}->settings')


# =================================
# WEBUI EXTENSIONS
# =================================
# webui template registrations
import source.main.dfe_template_globals

# webui themes
import source.main.dfe_themes

# LABEL: CODE_NOT_STABLE
# secure messenger extension
import source.messenger.msg_main

# =================================
# JINJA2 API - CUSTOM TEMPLATES
# =================================
app.jinja_env.filters['itoip'] = itoip

# =================================
# LABEL: DEVELOPMENT_ONLY_CODE
# =================================
# will only be registered if running on dev branch using flask dev server
server_type = os.environ.get('FLASK_ENV')
if (server_type == 'development'):

    @app.before_request
    def print_forms() -> None:
        if (request.method == 'POST'):
            print(f'form data\n{"=" * 12}')
            ppt(dict(request.form))

    @app.after_request
    def no_store_http_header(response):
        # matches primary html files only
        if ('.' not in request.path):
            response.headers.add('Cache-Control', 'no-store')

        return response
