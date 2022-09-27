#!/usr/bin/env python3

from __future__ import annotations

import os
from datetime import timedelta

from source.web_typing import *

from dnx_gentools.def_constants import HOME_DIR, FIVE_SEC, fast_time, ppt
from dnx_gentools.def_enums import CFG
from dnx_gentools.def_exceptions import ConfigurationError
from dnx_gentools.file_operations import load_configuration, ConfigurationManager

from dnx_iptools.cprotocol_tools.cprotocol_tools import itoip

from dnx_routines.database.ddb_connector_sqlite import DBConnector
from dnx_routines.logging import LogHandler as Log

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

general_error_page = 'main/general_error.html'
application_error_page = 'main/application_error.html'

# a new key is generated on every system start and stored in system config.
app_config = load_configuration('system', cfg_type='global')
app.secret_key = app_config['flask->key']

app.jinja_env.trim_blocks   = True
app.jinja_env.lstrip_blocks = True

# =========================================
# DNX API - LOGGING / FIREWALL / CONFIG
# =========================================
from dnx_control.control.ctl_action import system_action
from dnx_secmods.cfirewall.fw_control import FirewallControl

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
import source.rules.dfe_firewall as dnx_fwall
import source.rules.dfe_nat as dnx_nat
import source.intrusion.dfe_ip as ip_proxy
import source.intrusion.domain.dfe_domain as dns_proxy
import source.intrusion.domain.dfe_xlist as xlist
import source.intrusion.domain.dfe_categories as category_settings
import source.intrusion.dfe_ids_ips as dnx_ips
import source.system.settings.dfe_dns as dns_settings
import source.system.settings.dfe_dhcp as dhcp_settings
import source.system.settings.dfe_interface as interface_settings
import source.system.settings.dfe_logging as logging_settings
import source.system.settings.dfe_syslog as syslog_settings
import source.system.log.dfe_traffic as traffic_logs
import source.system.log.dfe_events as sec_events
import source.system.log.dfe_system as sys_logs
import source.system.dfe_users as dfe_users
import source.system.dfe_backups as dfe_backups
import source.system.dfe_services as dnx_services

dns_settings: StandardWebPage

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING
if (TYPE_CHECKING):
    from source.web_typing import Optional, Union, ConfigChain

from source.main.dfe_authentication import Authentication, user_restrict

# --------------------------------------------- #
#  START OF NAVIGATION TABS
# --------------------------------------------- #
# TODO: figure out best visually pleasing way to inject current logged in user info on each page.
@app.route('/dashboard', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def dnx_dashboard(session_data: dict):
    dashboard = dfe_dashboard.load_page()

    page_settings = {
        'navi': True, 'footer': True, 'standard_error': False,
        'idle_timeout': True, 'dashboard': dashboard,
        'uri_path': ['dashboard']
    }

    page_settings.update(session_data)

    return render_template('main/dashboard.html', theme=context_global.theme, **page_settings)

# --------------------------------------------- #
#  START OF RULES TAB
# --------------------------------------------- #
@app.route('/rules/firewall', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_firewall(session_data: dict):

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

    page_settings.update(session_data)

    page_action = firewall_page_logic(
        dnx_fwall, page_settings, 'firewall_settings', page_name='rules/firewall/firewall.html'
    )

    return page_action

@app.route('/rules/firewall/commit', methods=['POST'])
@user_restrict('admin')
def rules_firewall_commit(session_data: dict):

    # TODO: get user and ip information so we can log the commit (warning?)

    json_data = request.get_json(force=True)

    status, err_data = dnx_fwall.commit_rules(json_data)

    return ajax_response(status=status, data=err_data)

@app.route('/rules/firewall/push', methods=['POST'])
@user_restrict('admin')
def rules_firewall_push(session_data: dict):
    # for when we implement preview option
    # json_data = request.get_json(force=True)

    error = FirewallControl.push()
    if (error):
        return ajax_response(status=False, data={'error': 1, 'message': 'push failed'})

    return ajax_response(status=True, data={'error': 0, 'message': 'push success'})

@app.route('/rules/nat', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_nat(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'menu': validate.get_convert_int(request.args, 'menu'),
        'selected': 'WAN_ZONE',
        'zones': ['WAN', 'DMZ', 'LAN'],
        'uri_path': ['rules', 'nat']
    }

    page_settings.update(session_data)

    page_action = firewall_page_logic(
        dnx_nat, page_settings, 'nat_settings', page_name='rules/nat.html'
    )

    return page_action

# --------------------------------------------- #
#  START OF INTRUSION TAB
# --------------------------------------------- #
@app.route('/intrusion/ip', methods=['GET', 'POST'])
@user_restrict('admin')
def intrusion_ip(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'ajax': True,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': ['intrusion', 'ip']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        ip_proxy, page_settings, 'ip_settings', page_name='intrusion/ip.html'
    )

    return page_action

# TODO: work on proper response
@app.post('/intrusion/ip/post')
@user_restrict('admin')
def intrusion_ip_post(session_data: dict):

    json_data = request.get_json(force=True)

    status, err_data = ip_proxy.update_field(json_data)

    # print(f'[commit/response] status={status}, err_data={err_data}')

    return ajax_response(status=status, data=err_data)

@app.get('/intrusion/domain')
@user_restrict('admin')
def intrusion_domain(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'ajax': True,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': ['intrusion', 'domain']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dns_proxy, page_settings, 'domain_settings', page_name='intrusion/domain/domain.html'
    )

    return page_action

@app.post('/intrusion/domain/post')
@user_restrict('admin')
def intrusion_domain_post(session_data: dict):

    json_data = request.get_json(force=True)

    status, err_data = dns_proxy.update_page(json_data)

    # print(f'[commit/response] status={status}, err_data={err_data}')

    return ajax_response(status=status, data=err_data)

    #  START OF DOMAIN SUB MENU
    # ----------------------------------------- #
@app.route('/intrusion/domain/whitelist', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_overrides_whitelist(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': ['intrusion', 'domain', 'whitelist']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        xlist, page_settings, 'whitelist_settings', page_name='rules/overrides/whitelist.html'
    )

    return page_action

@app.route('/intrusion/domain/blacklist', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_overrides_blacklist(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': ['intrusion', 'domain', 'blacklist']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        xlist, page_settings, 'blacklist_settings', page_name='rules/overrides/blacklist.html'
    )

    return page_action

@app.route('/intrusion/domain/categories', methods=['GET', 'POST'])
@user_restrict('admin')
def intrusion_domain_categories(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'menu': validate.get_convert_int(request.args, 'menu'),
        'cat_settings': True,
        'uri_path': ['intrusion', 'domain', 'categories']
    }

    page_settings.update(session_data)

    page_action = categories_page_logic(category_settings, page_settings)

    return page_action

    #  END OF DOMAIN SUB MENU
    # ----------------------------------------- #
@app.route('/intrusion/ips', methods=['GET', 'POST'])
@user_restrict('admin')
def intrusion_ips(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': ['intrusion', 'ips']
    }

    page_settings.update(session_data)

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
def system_settings_dns(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': ['system', 'settings', 'dns']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dns_settings, page_settings, 'dns_settings', page_name='system/settings/dns.html'
    )

    return page_action

@app.route('/system/settings/dhcp', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_dhcp(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': ['system', 'settings', 'dhcp']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dhcp_settings, page_settings, 'dhcp_settings', page_name='system/settings/dhcp.html'
    )

    return page_action

@app.route('/system/settings/interface', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_interface(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': ['system', 'settings', 'interface']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        interface_settings, page_settings, 'interface_settings', page_name='system/settings/interface.html'
    )

    return page_action

@app.route('/system/settings/logging', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_logging(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': ['system', 'settings', 'logging']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        logging_settings, page_settings, 'logging_settings', page_name='system/settings/logging.html'
    )

    return page_action

@app.route('/system/settings/syslog', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_syslog(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_convert_int(request.args, 'tab'),
        'uri_path': ['system', 'settings', 'syslog']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        syslog_settings, page_settings, 'syslog_settings', page_name='system/settings/syslog.html'
    )

    return page_action

    # END OF SETTINGS SUB MENU
    # ----------------------------------------- #
@app.route('/system/log/traffic', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_logs_traffic(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'table': '1', 'dnx_table': True, 'ajax': False, 'auto_colorize': True,
        'table_types': ['firewall', '.nat'],
        'uri_path': ['system', 'log', 'traffic']
    }

    page_settings.update(session_data)

    page_action = log_page_logic(traffic_logs, page_settings, page_name='system/log/traffic/traffic.html')

    return page_action

@app.route('/system/log/events', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_logs_traffic_events(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'table': '1', 'dnx_table': True, 'ajax': False, 'auto_colorize': True,
        'table_types': ['dns_proxy', 'ip_proxy', 'intrusion_prevention', 'infected_clients'],
        'uri_path': ['system', 'log', 'events']
    }

    page_settings.update(session_data)

    page_action = log_page_logic(sec_events, page_settings, page_name='system/log/events/events.html')

    return page_action

@app.route('/system/log/system', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_logs_system(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'dnx_table': True, 'ajax': True, 'auto_colorize': True,
        'log_files': [
            'combined', 'logins', 'web_app', 'system', 'dns_proxy', 'ip_proxy', 'ips', 'dhcp_server',  # 'syslog'
        ],
        'uri_path': ['system', 'log', 'system']
    }

    page_settings.update(session_data)

    page_action = log_page_logic(sys_logs, page_settings, page_name='system/log/system/system.html')

    return page_action

@app.post('/system/log/system/get')
@user_restrict('user', 'admin')
def system_logs_get(session_data):
    json_data = request.get_json(force=True)

    _, _, table_data = sys_logs.update_page(json_data)

    return ajax_response(status=True, data=table_data)

@app.route('/system/users', methods=['GET', 'POST'])
@user_restrict('admin')
def system_users(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'uri_path': ['system', 'users']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dfe_users, page_settings, 'user_list', page_name='system/users.html'
    )

    return page_action

@app.route('/system/backups', methods=['GET', 'POST'])
@user_restrict('admin')
def system_backups(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'uri_path': ['system', 'backups']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dfe_backups, page_settings, 'current_backups', page_name='system/backups.html')

    return page_action

@app.route('/system/services', methods=['GET', 'POST'])
@user_restrict('admin')
def system_services(session_data: dict):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'uri_path': ['system', 'services']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dnx_services, page_settings, 'service_info', page_name='system/services.html')

    return page_action

# --------------------------------------------- #
#  START OF DEVICE MENU
# --------------------------------------------- #
@app.route('/device/<path>', methods=['GET', 'POST'])
@user_restrict('admin')
def system_restart(session_data, path):
    page_settings = {
        'navi': True, 'idle_timeout': False,
        'control': True, 'action': f'{path}',
        'uri_path': ['device', f'{path}']
    }

    page_settings.update(session_data)

    return handle_system_action(page_settings)

# --------------------------------------------- #
#  START OF LOGOUT MENU
# --------------------------------------------- #
@app.get('/logout')
@user_restrict('user', 'admin')
# removing user from session dict then removing them from locally stored session tracker to allow for cross session
# awareness of users/accounts logged in.
def dnx_logout(session_data: dict):
    user = session.pop('user', None)
    if (user):
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

        authenticated, username, user_role = Authentication.user_login(request.form, request.remote_addr)
        if (authenticated):
            update_session_tracker(username, user_role, request.remote_addr)

            session['user'] = username

            return redirect(url_for('dnx_dashboard'))

        page_settings['login_error'] = 'Invalid Credentials. Please try again.'

    return render_template('main/login.html', theme=context_global.theme, **page_settings)

# --------------------------------------------- #
#  BLOCKED PAGE | dns redirect
# --------------------------------------------- #
@app.route('/blocked')
def dnx_blocked() -> str:
    page_settings = {
        'navi': True, 'login_btn': True, 'idle_timeout': False,
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
        domain_info = firewall_db.execute('main/blocked_domain', domain=blocked_domain, src_ip=request.remote_addr)

    if (not domain_info):
        session.pop('user', None)

        return render_template('main/not_authorized.html', theme=context_global.theme, **page_settings)

    page_settings.update({'standard_error': False, 'src_ip': request.remote_addr, 'blocked': domain_info})

    return render_template('main/blocked.html', theme=context_global.theme, **page_settings)

# --------------------------------------------- #
# --------------------------------------------- #

@app.post('/refresh/session')
@user_restrict('user', 'admin')
def refresh_session(session_data: dict):

    return ajax_response(status=True, data={'error': 0, 'message': None})

# --------------------------------------------- #
# --------------------------------------------- #
@app.get('/')
def main():
    return redirect(url_for('dnx_login'))

# TODO: make this use a new non application error page because explanation doesnt make sense. also transfer session
#  of logged in users.
@app.route('/<path>', methods=['GET', 'POST'])
def default(path):

    return render_template(general_error_page, general_error=f'{path} not found.')

@app.route('/<path_a>/<path_b>', methods=['GET', 'POST'])
def default_sub(path_a, path_b):

    return render_template(general_error_page, general_error=f'{path_a}/{path_b} not found.')

@app.route('/<path_a>/<path_b>/<path_c>', methods=['GET', 'POST'])
def default_sub_sub(path_a, path_b, path_c):

    return render_template(general_error_page, general_error=f'{path_a}/{path_b}/{path_c} not found.')

# --------------------------------------------- #
# all standard page loads use this logic to decide the page action/ call the correct
# lower level functions residing in each page's module
def standard_page_logic(dnx_page: StandardWebPage, page_settings: dict, data_key: str, *, page_name: str) -> str:

    if (request.method == 'POST'):
        try:
            error, err_msg = dnx_page.update_page(request.form)
        except ConfigurationError as ce:
            return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

        page_settings.update({
            'tab': validate.get_convert_int(request.form, 'tab'),
            'standard_error': err_msg
        })

    try:
        page_settings[data_key] = dnx_page.load_page(request.form)
    except ConfigurationError as ce:
        return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

    return render_template(page_name, theme=context_global.theme, **page_settings)

def firewall_page_logic(dnx_page: ModuleType, page_settings: dict, data_key: str, *, page_name: str) -> str:

    if (request.method == 'POST'):
        try:
            error, selected = dnx_page.update_page(request.form)
        except ConfigurationError as ce:
            return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

        page_settings.update({
            'tab': validate.get_convert_int(request.form, 'tab'),
            'selected': selected,
            'standard_error': error
        })

    try:
        page_settings[data_key] = dnx_page.load_page(page_settings['selected'])
    except ConfigurationError as ce:
        return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

    return render_template(page_name, theme=context_global.theme, **page_settings)

def log_page_logic(log_page: ModuleType, page_settings: dict, *, page_name: str) -> str:
    # can now accept redirects from other places on the webui to load specific tables directly on load
    # using uri queries FIXME: this has been temporarily suspended and should be reintroduced.

    try:
        table, menu, table_data = log_page.update_page(request.form)
    except ConfigurationError as ce:
        return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

    page_settings.update({
        'table': table,
        'menu': menu,
        'table_data': table_data
    })

    return render_template(page_name, theme=context_global.theme, **page_settings)

def categories_page_logic(dnx_page: ModuleType, page_settings: dict) -> str:
    if (request.method == 'POST'):
        try:
            error, menu_option = dnx_page.update_page(request.form)
        except ConfigurationError as ce:
            return render_template(application_error_page, application_error=ce, theme=context_global.theme, **page_settings)

        page_settings.update({
            'tab': validate.get_convert_int(request.args, 'tab'),
            'menu': validate.get_convert_int(request.args, 'menu'),
            'standard_error': error
        })

    try:
        page_settings['category_settings'] = dnx_page.load_page(page_settings['menu'])
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

def update_session_tracker(username: str, user_role: Optional[str] = None, remote_addr: Optional[str] = None,
                           *, action: CFG = CFG.ADD) -> None:

    if (action is CFG.ADD and not remote_addr):
        raise ValueError('remote_addr must be specified if action is set to add.')

    with ConfigurationManager('session_tracker', file_path='dnx_webui/data') as session_tracker:
        persistent_tracker: ConfigChain = session_tracker.load_configuration()

        user_path = f'active_users->{username}'
        if (action is CFG.ADD):

            persistent_tracker[f'{user_path}->role'] = user_role
            persistent_tracker[f'{user_path}->remote_addr'] = remote_addr
            persistent_tracker[f'{user_path}->logged_in'] = fast_time()  # NOTE: make human-readable?
            persistent_tracker[f'{user_path}->last_seen'] = None

        elif (action is CFG.DEL):
            try:
                del persistent_tracker[f'active_users->{username}']
            except KeyError:
                pass

        session_tracker.write_configuration(persistent_tracker.expanded_user_data)

def ajax_response(*, status: bool, data: Union[dict, list]):
    if (not isinstance(status, bool)):
        raise TypeError('Ajax response status must be a boolean.')

    # print(jsonify({'success': status, 'result': data}))

    return jsonify({'success': status, 'result': data})

def authenticated_session() -> Optional[str]:
    return session.get('user', None)

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
            webui_settings = webui.load_configuration()

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

@app.before_request
def set_theme_values() -> None:
    theme = context_global.theme = {
        'mode': context_global.settings['theme'],  # // for now until we pass all settings into template context
        'nav_text': 'blue-grey-text text-darken-2',
        'subnav_text': 'blue-grey-text text-darken-3',
        'tab_text': 'blue-grey-text text-lighten-2',
        'tab_classes': 'tab col s4 l3 xl2',
        'icon': 'teal-text text-lighten-2',
        'modal_text': 'blue-grey-text center',
    }

    if (context_global.settings['theme'] == 'dark'):
        theme.update({
            'background': (
                'style="background: url(static/assets/images/dnx_bg1_dark.svg); '
                'background-repeat: repeat; '
                'background-attachment: fixed;"'
            ),
            'main_section': 'blue-grey lighten-2',
            'off_section': 'blue-grey lighten-5',
            'card': 'blue-grey lighten-4',
            'title': 'black-text'
        })

    elif (context_global.settings['theme'] == 'light'):
        theme.update({
            'background': (
                'style="background: url(static/assets/images/dnx_bg1_light.svg); '
                'background-repeat: repeat; '
                'background-attachment: fixed;"'
            ),
            'main_section': 'grey lighten-2',
            'off_section': 'grey lighten-5',
            'card': 'grey lighten-4',
            'title': 'blue-grey-text text-darken-1'
        })

# ====================================
# FLASK API - TEMPLATE FUNCTIONS
# ====================================
@app.template_global()
def create_title(title: str) -> str:
    return (
        f'<div class="row"><h4 class="{context_global.theme["title"]} card-title">{title.title()}</h4></div>'
        f'<div class="title-divider"></div><br>'
    )

@app.template_global()
def create_switch(label: str, name: str, *, tab: int = 1, checked: int = 0, enabled: int = 1) -> str:
    if (not enabled): status = 'disabled'
    elif (checked): status = 'checked'
    else: status = ''

    return ''.join([
        f'<form method="POST"><input type="hidden" name="tab" value="{tab}">',
        f'<div class="input-field col s6 center">{label}<div class="switch"><label>Off',
        f'<input type="checkbox" class="iswitch" name="{name}" {status}>',
        '<span class="lever"></span>On</label></div></div></form>'
    ])

@app.template_global()
def create_tab(active_tab: int, cur_tab: int, href: str) -> str:
    tab = (
        f'<li class="{context_global.theme["tab_classes"]}">'
        f'<a href="#{href}" onclick="activeTab({cur_tab})" class="{context_global.theme["tab_text"]}'
    )

    if (cur_tab == active_tab):
        tab += ' active'

    tab += f'">{href.replace("-", " ").title()}</a></li>'

    return tab

@app.template_global()
def create_button_with_modal(
        classes: str, icon: str, index: int, num: int, tab: int, btn_name: str, btn_value: str, message: str) -> str:

    btn_classes = f'{classes} waves-effect waves-light modal-trigger'

    button = (
        f'<a class="{btn_classes}" href="#modal{index}-{num}"><i class="material-icons">{icon}</i></a>'
        f'<div id="modal{index}-{num}" class="modal">'
          f'<div class="modal-content"><h5 class="{context_global.theme["modal_text"]}">{message}</h5></div>'
          f'<form method="POST"><input type="hidden" name="tab" value="{tab}">'
            '<div class="modal-footer">'
              f'<button name="{btn_name}" value="{btn_value}" class="btn waves-effect waves-light">YES</button>'
              '<a class="modal-close waves-effect waves-green btn-flat">Cancel</a>'
            '</div>'
          '</form>'
        '</div>'
    )

    return button

@app.template_global()
def create_decora_switch(name: str, value: str, enabled: int):

    off = ' active' if not enabled else ''
    on  = ' active' if enabled else ''

    switch = (
        f'<div class="col s3"><div class="row row-thin"><p class="multi-switch-label center">{value}</p></div>'
        '<div class="row row-thin"><div class="multi-switch-container decora-switch">'
        '<ul class="multi-switch">'
            f'<li class="multi-switch-off{off}"><button name="{name}" value="{value}" onclick="updateCategory(this, 0)">'
                '<i class="material-icons small">radio_button_unchecked</i></button></li>'
            f'<li class="multi-switch-on{on}"><button name="{name}" value="{value}" onclick="updateCategory(this, 1)">'
                '<i class="material-icons small">block</i></button></li>'
        '</ul></div></div></div>'
    )

    return switch

@app.template_global()
def merge_items(a1, a2):
    '''accepts 2 arguments of item or list and merges them into one list. int can be replaced with any singular object.

        valid combinations.
            (int, list)
            (int, int)
            (list,list)
            (list, int)
    '''
    new_list = []

    for arg in [a1, a2]:

        if not isinstance(arg, str) and hasattr(arg, '__iter__'):
            new_list.extend(arg)

        else:
            new_list.append(arg)

    return new_list

@app.template_global()
def is_list(li, /) -> bool:
    return isinstance(li, list)


# ====================================
# JINJA2 API - CUSTOM TEMPLATES
# ====================================
app.jinja_env.filters['itoip'] = itoip

# =================================
# DEV ONLY
# =================================
# function will only be registered if running on dev branch using flask dev server
server_type = os.environ.get('FLASK_ENV')
if (server_type == 'development'):

    @app.before_request
    def print_forms() -> None:
        if (request.method == 'POST'):
            print(f'form data\n{"=" * 12}')
            ppt(dict(request.form))
