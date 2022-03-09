#!/usr/bin/env python3

from __future__ import annotations

from typing import Optional

from datetime import timedelta

import dnx_routines.configure.web_validate as validate

from dnx_gentools.def_constants import HOME_DIR, FIVE_SEC, fast_time
from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.def_exceptions import ValidationError
from dnx_gentools.file_operations import load_configuration, ConfigurationManager

from dnx_routines.database.ddb_connector_sqlite import DBConnector

from dnx_routines.logging import LogHandler as Log

# ========================================
# FLASK API - APP INSTANCE INITIALIZATION
# ========================================
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

app = Flask(
    __name__, static_folder=f'{HOME_DIR}/dnx_webui/static', template_folder=f'{HOME_DIR}/dnx_webui/templates'
)

# easy access to app instance by outer components
Flask.app = app

general_error_page = 'main/general_error.html'
application_error_page = 'main/application_error.html'

# a new key is generated on every system start and stored in system config.
app_config = load_configuration('system')
app.secret_key = app_config['flask->key']

# =========================================
# DNX API - LOGGING / FIREWALL / CONFIG
# =========================================
from dnx_system.sys_action import system_action
from dnx_secmods.cfirewall.fw_manage import FirewallManage

import dnx_webui.source.main.dfe_obj_manager as dnx_object_manager

# setup for system logging
Log.run(name='web_app')

# NOTE: this will allow the config manager to reference the Log class without an import. (cyclical import error)
ConfigurationManager.set_log_reference(Log)

app.dnx_object_manager = dnx_object_manager.initialize(HOME_DIR)

# initialize cfirewall manager, which interfaces with cfirewall control class through a fd.
cfirewall = FirewallManage()

# setting FirewallManager instance as class var within FirewallManager to access instance through webui
FirewallManage.cfirewall = cfirewall

# setting object manager instance as class var within FirewallManager for direct access
FirewallManage.object_manager = app.dnx_object_manager

# =========================================
# WEBUI COMPONENTS
# =========================================
import source.main.dfe_dashboard as dfe_dashboard
import source.rules.dfe_firewall as dnx_fwall
import source.rules.dfe_nat as dnx_nat
import source.rules.dfe_xlist as xlist
import source.intrusion.dfe_ip as ip_proxy
import source.intrusion.domain.dfe_domain as dns_proxy
import source.intrusion.domain.dfe_categories as category_settings
import source.intrusion.dfe_ips as dnx_ips
import source.system.settings.dfe_dns as dns_settings
import source.system.settings.dfe_dhcp as dhcp_settings
import source.system.settings.dfe_interface as interface_settings
import source.system.settings.dfe_logging as logging_settings
import source.system.settings.dfe_syslog as syslog_settings
import source.system.dfe_logs as dfe_logs
import source.system.dfe_reports as proxy_reports
import source.system.dfe_users as dfe_users
import source.system.dfe_backups as dfe_backups
import source.system.dfe_services as dnx_services

from source.main.dfe_authentication import Authentication, user_restrict

# --------------------------------------------- #
#  START OF NAVIGATION TABS
# --------------------------------------------- #
# TODO: figure out best visually pleasing way to inject current logged in user info on each page.
@app.route('/dashboard', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def dnx_dashboard(session_data):
    dashboard = dfe_dashboard.load_page()

    page_settings = {
        'navi': True, 'footer': True, 'standard_error': False,
        'idle_timeout': True, 'dashboard': dashboard,
        'uri_path': ['dashboard']
    }

    page_settings.update(session_data)
    print(page_settings)

    return render_template('main/dashboard.html', **page_settings)

# --------------------------------------------- #
#  START OF RULES TAB
# --------------------------------------------- #
@app.route('/rules/firewall', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_firewall(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'ajax': True,
        'tab': validate.get_check_digit(request.args, 'tab'),
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
def rules_firewall_commit(session_data):

    # TODO: get user and ip information so we can log the commit (warning?)

    json_data = request.get_json(force=True)
    print(json_data)

    status, err_data = dnx_fwall.commit_rules(json_data)

    print(f'[commit/response] status={status}, err_data={err_data}')

    return ajax_response(status=status, data=err_data)

@app.route('/rules/nat', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_nat(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_check_digit(request.args, 'tab'),
        'menu': validate.get_check_digit(request.args, 'menu'),
        'selected': 'WAN_ZONE',
        'zones': ['WAN', 'DMZ', 'LAN'],
        'uri_path': ['rules', 'nat']
    }

    page_settings.update(session_data)

    page_action = firewall_page_logic(
        dnx_nat, page_settings, 'nat_settings', page_name='rules/nat.html'
    )

    return page_action

@app.route('/rules/overrides/whitelist', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_overrides_whitelist(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_check_digit(request.args, 'tab'),
        'uri_path': ['rules', 'overrides', 'whitelist']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        xlist, page_settings, 'whitelist_settings', page_name='rules/overrides/whitelist.html'
    )

    return page_action

@app.route('/rules/overrides/blacklist', methods=['GET', 'POST'])
@user_restrict('admin')
def rules_overrides_blacklist(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_check_digit(request.args, 'tab'),
        'uri_path': ['rules', 'overrides', 'blacklist']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        xlist, page_settings, 'blacklist_settings', page_name='rules/overrides/blacklist.html'
    )

    return page_action

# --------------------------------------------- #
#  START OF INTRUSION TAB
# --------------------------------------------- #
@app.route('/intrusion/ip', methods=['GET', 'POST'])
@user_restrict('admin')
def intrusion_ip(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'ajax': True,
        'tab': validate.get_check_digit(request.args, 'tab'),
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
def intrusion_ip_post(session_data):

    json_data = request.get_json(force=True)
    print(json_data)

    status, err_data = ip_proxy.update_field(json_data)

    print(f'[commit/response] status={status}, err_data={err_data}')

    return ajax_response(status=status, data=err_data)

@app.route('/intrusion/domain', methods=['GET', 'POST'])
@user_restrict('admin')
def intrusion_domain(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'ajax': True,
        'tab': validate.get_check_digit(request.args, 'tab'),
        'uri_path': ['intrusion', 'domain']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dns_proxy, page_settings, 'domain_settings', page_name='intrusion/domain/domain.html'
    )

    return page_action

@app.post('/intrusion/domain/post')
@user_restrict('admin')
def intrusion_domain_post(session_data):

    json_data = request.get_json(force=True)
    print(json_data)

    status, err_data = dns_proxy.update_page(json_data)

    print(f'[commit/response] status={status}, err_data={err_data}')

    return ajax_response(status=status, data=err_data)

    #  START OF DOMAIN SUB MENU
    # ----------------------------------------- #
@app.route('/intrusion/domain/categories', methods=['GET', 'POST'])
@user_restrict('admin')
def intrusion_domain_categories(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_check_digit(request.args, 'tab'),
        'menu': validate.get_check_digit(request.args, 'menu'),
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
def intrusion_ips(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_check_digit(request.args, 'tab'),
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
def system_settings_dns(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_check_digit(request.args, 'tab'),
        'uri_path': ['system', 'settings', 'dns']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dns_settings, page_settings, 'dns_settings', page_name='system/settings/dns.html'
    )

    return page_action

@app.route('/system/settings/dhcp', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_dhcp(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_check_digit(request.args, 'tab'),
        'uri_path': ['system', 'settings', 'dhcp']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dhcp_settings, page_settings, 'dhcp_settings', page_name='system/settings/dhcp.html'
    )

    return page_action

@app.route('/system/settings/interface', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_interface(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_check_digit(request.args, 'tab'),
        'uri_path': ['system', 'settings', 'interface']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        interface_settings, page_settings, 'interface_settings', page_name='system/settings/interface.html'
    )

    return page_action

@app.route('/system/settings/logging', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_logging(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_check_digit(request.args, 'tab'),
        'uri_path': ['system', 'settings', 'logging']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        logging_settings, page_settings, 'logging_settings', page_name='system/settings/logging.html'
    )

    return page_action

@app.route('/system/settings/syslog', methods=['GET', 'POST'])
@user_restrict('admin')
def system_settings_syslog(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': validate.get_check_digit(request.args, 'tab'),
        'uri_path': ['system', 'settings', 'syslog']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        syslog_settings, page_settings, 'syslog_settings', page_name='system/settings/syslog.html'
    )

    return page_action

    # END OF SETTINGS SUB MENU
    # ----------------------------------------- #
@app.route('/system/logs', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_system_logs(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'dnx_table': True, 'ajax': True, 'auto_colorize': True,
        'log_files': [
            'combined', 'logins', 'web_app', 'system', 'dns_proxy', 'ip_proxy', 'ips', 'dhcp_server', 'syslog'
        ],
        'uri_path': ['system', 'logs']
    }

    page_settings.update(session_data)

    page_action = log_page_logic(dfe_logs, page_settings, page_name='system/logs/logs.html')

    return page_action

@app.post('/system/logs/get')
@user_restrict('user', 'admin')
def system_logs_get(session_data):
    json_data = request.get_json(force=True)

    table_data, _, _ = dfe_logs.update_page(json_data)

    return ajax_response(status=True, data=table_data)

@app.route('/system/reports', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_reports(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'table': '1', 'dnx_table': True, 'ajax': False, 'auto_colorize': True,
        'table_types': ['dns_proxy', 'ip_proxy', 'intrusion_prevention', 'infected_clients'],
        'uri_path': ['system', 'reports']
    }

    page_settings.update(session_data)

    page_action = log_page_logic(proxy_reports, page_settings, page_name='system/reports.html')

    return page_action

@app.route('/system/users', methods=['GET', 'POST'])
@user_restrict('admin')
def system_users(session_data):
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
def system_backups(session_data):
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
def system_services(session_data):
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
@app.route('/device/restart', methods=['GET', 'POST'])
@user_restrict('admin')
def system_restart(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': False,
        'control': True, 'action': 'restart',
        'uri_path': ['device', 'restart']
    }

    page_settings.update(session_data)

    return handle_system_action(page_settings)

@app.route('/device/shutdown', methods=['GET', 'POST'])
@user_restrict('admin')
def system_shutdown(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': False,
        'control': True, 'action': 'shutdown',
        'uri_path': ['device', 'shutdown']
    }

    page_settings.update(session_data)

    return handle_system_action(page_settings)

# --------------------------------------------- #
#  START OF LOGOUT MENU
# --------------------------------------------- #
@app.route('/logout', methods=['GET'])
@user_restrict('user', 'admin')
# removing user from session dict then removing them from locally stored session tracker to allow for cross session
# awareness of users/accounts logged in.
def dnx_logout(session_data):
    user = session.pop('user', None)
    if (user):
        update_session_tracker(user['name'], action=CFG.DEL)

    return redirect(url_for('dnx_login'))

# --------------------------------------------- #
#  BLOCKED PAGE | dns redirect
# --------------------------------------------- #
@app.route('/blocked')
def dnx_blocked():
    page_settings = {
        'navi': True, 'login_btn': True, 'idle_timeout': False,
        'uri_path': ['blocked']
    }

    # checking for domain sent by nginx that is being redirected to rules. if domain doesnt exist (user navigated to
    # this page manually) then a not authorized page will be served. If the domain is not a valid domain (regex) the
    # request will be redirected back to blocked page without a domain.
    # NOTE: this is a crazy bit of code that should be tested much more as it is possible to do a sql injection here
    #  if the validations below are bypassed.
    blocked_domain = request.args.get('dom', None)
    if (not blocked_domain):
        session.pop('user', None)

        return render_template('main/not_authorized.html', **page_settings)

    try:
        validate.domain_name(blocked_domain)
    except ValidationError:
        session.pop('user', None)

        return render_template('main/not_authorized.html', **page_settings)

    with DBConnector() as firewall_db:
        domain_info = firewall_db.execute(
            'main/blocked_domain', domain=blocked_domain, src_ip=request.remote_addr
        )

    if (not domain_info):
        session.pop('user', None)

        return render_template('main/not_authorized.html', **page_settings)

    page_settings.update({
        'standard_error': False, 'src_ip': request.remote_addr, 'blocked': domain_info
    })

    return render_template('main/blocked.html', **page_settings)

# --------------------------------------------- #
# --------------------------------------------- #

@app.route('/login', methods=['GET', 'POST'])
def dnx_login():

    # user has an active authenticated session, so we can drop them back to the dashboard.
    if (session.get('user', None)):
        return redirect(url_for('dnx_dashboard'))

    login_error = None
    if (request.method == 'POST'):
        authenticated, username, user_role = Authentication.user_login(request.form, request.remote_addr)

        if (authenticated):
            update_session_tracker(username, user_role, request.remote_addr)

            session['user'] = username

            return redirect(url_for('dnx_dashboard'))

        login_error = 'Invalid Credentials. Please try again.'

    return render_template(
        'main/login.html', navi=False, login_btn=False, idle_timeout=False,
        standard_error=False, login_error=login_error, uri_path=['login']
    )

@app.post('/refresh/session')
@user_restrict('user', 'admin')
@user_restrict('user', 'admin')
def refresh_session(dnx_session):

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
# lower level functions residing in each page's Class
def standard_page_logic(dnx_page, page_settings, data_key, *, page_name):

    if (request.method == 'POST'):
        try:
            error = dnx_page.update_page(request.form)
        except OSError as ose:
            return render_template(application_error_page, application_error=ose, **page_settings)

        page_settings.update({
            'tab': validate.get_check_digit(request.args, 'tab'),
            'standard_error': error
        })

    try:
        page_settings[data_key] = dnx_page.load_page(request.form)
    except OSError as ose:
        return render_template(application_error_page, application_error=ose, **page_settings)

    print(request.args, page_settings)

    return render_template(page_name, **page_settings)

def firewall_page_logic(dnx_page, page_settings, data_key, *, page_name):

    if (request.method == 'POST'):
        try:
            error, selected = dnx_page.update_page(request.form)
        except OSError as ose:
            return render_template(application_error_page, application_error=ose, **page_settings)

        page_settings.update({
            'tab': validate.get_check_digit(request.args, 'tab'),
            'selected': selected,
            'standard_error': error
        })

    try:
        page_settings[data_key] = dnx_page.load_page()
    except OSError as ose:
        return render_template(application_error_page, application_error=ose, **page_settings)

    return render_template(page_name, **page_settings)

def log_page_logic(log_page, page_settings, *, page_name):
    # can now accept redirects from other places on the webui to load specific tables directly on load
    # using uri queries

    if (request.method == 'GET'):
        request_data, handler = request.args, log_page.load_page

    elif (request.method == 'POST'):
        request_data, handler = request.form, log_page.update_page

    else: return

    try:
        table_data, table, menu_option = handler(request_data)
    except OSError as ose:
        return render_template(application_error_page, application_error=ose, **page_settings)

    page_settings.update({
        'menu': menu_option,
        'table': table,
        'table_data': table_data
    })

    return render_template(page_name, **page_settings)

def categories_page_logic(dnx_page, page_settings):
    if (request.method == 'POST'):
        try:
            error, menu_option = dnx_page.update_page(request.form)
        except OSError as ose:
            return render_template(application_error_page, application_error=ose, **page_settings)

        page_settings.update({
            'tab': validate.get_check_digit(request.args, 'tab'),
            'menu': validate.get_check_digit(request.args, 'menu'),
            'standard_error': error
        })

    try:
        page_settings['category_settings'] = dnx_page.load_page(page_settings['menu'])
    except OSError as ose:
        return render_template(application_error_page, application_error=ose, **page_settings)

    return render_template('intrusion/domain/categories.html', **page_settings)

# function called by restart/shutdown pages. will ensure the user specified operation gets executed
def handle_system_action(page_settings):
    action = page_settings['action']

    response = request.form.get(f'system_{action}', None)
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

    return render_template('main/device.html', **page_settings)

def update_session_tracker(username: str, user_role: Optional[str] = None, remote_addr: Optional[str] = None,
                           *, action: CFG = CFG.ADD):

    if (action is CFG.ADD and not remote_addr):
        raise ValueError('remote_addr must be specified if action is set to add.')

    with ConfigurationManager('session_tracker', file_path='dnx_webui/data') as session_tracker:
        persistent_tracker = session_tracker.load_configuration()

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

def ajax_response(*, status, data):
    if (not isinstance(status, bool)):
        raise TypeError('Ajax response status must be a boolean.')

    print(jsonify({'success': status, 'result': data}))

    return jsonify({'success': status, 'result': data})

# =================================
# FLASK API - REQUEST MODS
# =================================
@app.before_request
def user_timeout():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

# checks form data for a color mode change and writes/ configures accordingly. otherwise, will load
# the current dark mode setting for the active user and set flask.session['dark_mode] accordingly.
@app.before_request
def dark_mode():
    '''
    the configured value will be stored as session['dark_mode'] so it can be accessed directly by the
    Flask template context.
    '''
    # dark mode settings will only apply to logged-in users.
    # NOTE: username validations are still required lower down to deal with log in/out transitions.
    user = session.get('user', None)
    if (not user):
        return

    dark_mode_update = request.args.get('dark_mode_update', DATA.MISSING)
    # this ensures value conforms to the system before configuring
    if (dark_mode_update is not DATA.MISSING):
        try:
            dark_mode_config = CFG(validate.convert_int(dark_mode_update))
        except:
            return

        with ConfigurationManager('logins', file_path='/dnx_webui/data') as webui:
            webui_settings = webui.load_configuration()

            active_users = webui_settings.get_list('users')

            # this check prevents issues with log in/out transitions
            if (user not in active_users):
                return

            webui_settings[f'active_users->{user}->dark_mode'] = dark_mode_config

            webui.write_configuration(webui_settings.expanded_user_data)

    # standard request for page. did NOT submit dark mode fab.
    else:
        webui_settings = load_configuration('logins', filepath='dnx_webui/data')

        # TODO: implement .get for ConfigChain dict
        # this check prevents issues with log in/out transitions
        dark_mode_config = webui_settings.get(f'users->{user}->dark_mode')
        if (not dark_mode_config):
            return

    session['dark_mode'] = dark_mode_config

# ====================================
# FLASK API - JINJA FILTER FUNCTIONS
# ====================================
def merge_items(a1, a2):
    '''accepts 2 arguments of item or list and merges them into one list.

        valid combinations. int can be replaced with any singular object.
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

def format_fw_obj(fw_obj, /):
    properties = {
        'country': ['red', 'language'], 'address': ['blue lighten-2', 'tv'],
        'service': ['orange lighten-2', 'track_changes']
    }.get(fw_obj[3], ['', ''])

    return (f'<div class="chip tooltipped {properties[0]}" data-html="true"'
            f'data-tooltip="<p style=width:160px> {fw_obj[2]}<br>{fw_obj[3]}<br>{fw_obj[4]}<br>{fw_obj[5]}</p>">'
            f'<i class="material-icons tiny {properties[0]} valign-center">{properties[1]}</i>  {fw_obj[1]}</div>')

def is_list(li, /):
    return isinstance(li, list)

def _debug(obj, /):
    print(obj)


app.add_template_global(merge_items, name='merge_items')
app.add_template_global(format_fw_obj, name='format_fw_obj')
app.add_template_global(is_list, name='is_list')
app.add_template_global(_debug, name='debug')
