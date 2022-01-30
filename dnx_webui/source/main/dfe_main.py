#!/usr/bin/env python3

# for running with flask dev server
if (__name__ == '__main__'):
    pass

import os
import time

from datetime import timedelta

import dnx_routines.configure.web_validate as validate

from dnx_gentools.def_constants import CFG, DATA, FIVE_SEC
from dnx_gentools.file_operations import load_configuration, ConfigurationManager
from dnx_routines.configure.exceptions import ValidationError
from dnx_routines.database.ddb_connector_sqlite import DBConnector
from dnx_routines.logging.log_main import LogHandler as Log

# ========================================
# FLASK API - APP INSTANCE INITIALIZATION
# ========================================
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

HOME_DIR = os.environ.get('HOME_DIR', '/home/dnx/dnxfirewall')

app = Flask(
    __name__, static_folder=f'{HOME_DIR}/dnx_webui/static', template_folder=f'{HOME_DIR}/dnx_webui/templates'
)

# easy access to app instance by outer components
Flask.app = app

application_error_page = 'main/general_error.html'

# a new key is generated on every system start and stored in system config.
app.secret_key = load_configuration('config')['flask'].get('key')

# =========================================
# DNX API - LOGGING / FIREWALL / CONFIG
# =========================================
from dnx_system.sys_action import system_action
from dnx_secmods.cfirewall.fw_manage import FirewallManage

import dnx_webui.source.main.dfe_obj_manager as dnx_object_manager

LOG_NAME = 'web_app'

# setup for system logging
Log.run(name=LOG_NAME)

# initialize cfirewall manager, which interfaces with cfirewall control class through a fd.
cfirewall = FirewallManage()

# setting ref class var to instance. this will allow any webui module to access firewall
# state without passing around object.
FirewallManage.cfirewall = cfirewall

# NOTE: this will allow the config manager to reference the Log class without an import. (cyclical import error)
ConfigurationManager.set_log_reference(Log)

app.dnx_object_manager = dnx_object_manager.initialize(HOME_DIR)

# =========================================
# WEBUI COMPONENTS
# =========================================
import dnx_webui.source.main.dfe_dashboard as dfe_dashboard
import dnx_webui.source.settings.dfe_dns as dns_settings
import dnx_webui.source.settings.dfe_dhcp as dhcp_settings
import dnx_webui.source.settings.dfe_interface as interface_settings
import dnx_webui.source.settings.dfe_logging as logging_settings
import dnx_webui.source.settings.dfe_syslog as syslog_settings
import dnx_webui.source.settings.dfe_categories as category_settings
import dnx_webui.source.advanced.dfe_whitelist as whitelist
import dnx_webui.source.advanced.dfe_blacklist as blacklist
import dnx_webui.source.advanced.dfe_firewall as dnx_fwall
import dnx_webui.source.advanced.dfe_nat as dnx_nat
import dnx_webui.source.advanced.dfe_domain as dns_proxy
import dnx_webui.source.advanced.dfe_ip as ip_proxy
import dnx_webui.source.advanced.dfe_ips as dnx_ips
import dnx_webui.source.system.dfe_logs as dfe_logs
import dnx_webui.source.system.dfe_reports as proxy_reports
import dnx_webui.source.system.dfe_users as dfe_users
import dnx_webui.source.system.dfe_backups as dfe_backups
import dnx_webui.source.system.dfe_services as dnx_services

from dnx_webui.source.main.dfe_authentication import Authentication, user_restrict

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

    return render_template('main/dashboard.html', **page_settings)

# --------------------------------------------- #
#  START OF SETTINGS TAB
# --------------------------------------------- #

@app.route('/settings/dns', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_dns(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['settings', 'dns']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dns_settings, page_settings, 'dns_settings', page_name='settings/dns')

    return page_action

@app.route('/settings/dhcp', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_dhcp(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['settings', 'dhcp']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dhcp_settings, page_settings, 'dhcp_settings' , page_name='settings/dhcp')

    return page_action

@app.route('/settings/interface', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_interface(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['settings', 'interface']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        interface_settings, page_settings, 'interface_settings', page_name='settings/interface')

    return page_action

@app.route('/settings/logging', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_logging(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['settings', 'logging']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        logging_settings, page_settings, 'logging_settings', page_name='settings/logging')

    return page_action

@app.route('/settings/syslog', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_syslog(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['settings', 'syslog']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        syslog_settings, page_settings, 'syslog_settings', page_name='settings/syslog')

    return page_action

@app.route('/settings/categories', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_categories(session_data):
    tab = request.args.get('tab', '1')
    menu_option = request.args.get('menu', '1')
    menu_option = int(menu_option) if menu_option.isdigit() else '1'

    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'cat_settings': True, 'tab': tab, 'menu': menu_option,
        'uri_path': ['settings', 'categories']
    }

    page_settings.update(session_data)

    page_action = categories_page_logic(category_settings, page_settings)

    return page_action

# --------------------------------------------- #
#  START OF ADVANCED TAB
# --------------------------------------------- #

@app.route('/advanced/whitelist', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_whitelist(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['advanced', 'whitelist']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        whitelist, page_settings, 'whitelist_settings', page_name='advanced/whitelist')

    return page_action

@app.route('/advanced/blacklist', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_blacklist(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['advanced', 'blacklist']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        blacklist, page_settings, 'blacklist_settings', page_name='advanced/blacklist')

    return page_action

@app.route('/advanced/firewall', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_firewall(session_data):
    tab = request.args.get('tab', '1')

    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'firewall': True, 'ajax': True, 'dnx_table': True,  # TODO: dnx_table can probably be removed
        'dnx_network_objects': {},
        'dnx_service_objects': {},
        'selected': 'MAIN',
        'sections': ['BEFORE', 'MAIN', 'AFTER'],
        'uri_path': ['advanced', 'firewall']
    }

    page_settings.update(session_data)

    page_action = firewall_page_logic(
        dnx_fwall, page_settings, 'firewall_settings', page_name='advanced/firewall/firewall')

    return page_action

@app.route('/advanced/firewall/commit', methods=['POST'])
@user_restrict('admin')
def advanced_firewall_commit(session_data):

    # TODO: get user and ip information so we can log the commit (warning?)

    json_data = request.get_json(force=True)
    print(json_data)

    status, err_data = dnx_fwall.commit_rules(json_data)

    print(f'[commit/response] status={status}, err_data={err_data}')

    return ajax_response(status=status, data=err_data)

@app.route('/advanced/nat', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_nat(session_data):
    tab = request.args.get('tab', '1')
    menu_option = request.args.get('menu', '1')

    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'menu': menu_option,
        'selected': 'WAN_ZONE',
        'zones': ['WAN', 'DMZ', 'LAN'],
        'uri_path': ['advanced', 'nat']
    }

    page_settings.update(session_data)

    page_action = firewall_page_logic(
        dnx_nat, page_settings, 'nat_settings', page_name='advanced/nat')

    return page_action

@app.route('/advanced/domain', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_domain(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['advanced', 'domain']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dns_proxy, page_settings, 'domain_settings', page_name='advanced/domain')

    return page_action

@app.route('/advanced/ip', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_ip(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['advanced', 'ip']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        ip_proxy, page_settings, 'ip_settings', page_name='advanced/ip')

    return page_action

@app.route('/advanced/ips', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_ips(session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['advanced', 'ips']
    }

    page_settings.update(session_data)

    page_action = standard_page_logic(
        dnx_ips, page_settings, 'ips_settings', page_name='advanced/ips')

    return page_action

# --------------------------------------------- #
#  START OF SYSTEMS TAB
# --------------------------------------------- #

@app.route('/system/logs', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_logs(session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'dnx_table': True, 'ajax': True, 'auto_colorize': True,
        'log_files': [
            'combined', 'logins', 'web_app', 'system', 'dns_proxy', 'ip_proxy', 'ips', 'dhcp_server', 'syslog'
        ],
        'uri_path': ['system', 'logs']
    }

    page_settings.update(session_data)

    page_action = log_page_logic(dfe_logs, page_settings, page_name='system/logs')

    return page_action

@app.route('/system/logs/get', methods=['POST',])
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
        'uri_path': ['system', 'reports'],
        'table_types': ['dns_proxy', 'ip_proxy', 'intrusion_prevention', 'infected_clients']
    }

    page_settings.update(session_data)

    page_action = log_page_logic(proxy_reports, page_settings, page_name='system/reports')

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
        dfe_users, page_settings, 'user_list', page_name='system/users')

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
        dfe_backups, page_settings, 'current_backups', page_name='system/backups')

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
        dnx_services, page_settings, 'service_info', page_name='system/services')

    return page_action

# --------------------------------------------- #
#  START OF DEVICE TAB
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
#  START OF LOGOUT TAB
# --------------------------------------------- #

@app.route('/logout', methods=['GET'])
@user_restrict('user', 'admin')
# removing user from session dict then removing them from locally stored session tracker to allow
# for cross session awareness of users/accts logged in.
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
        'navi': True, 'login_btn': True,
        'idle_timeout': False, 'uri_path': ['blocked']
    }

    # checking for domain sent by nginx that is being redirected to firewall. if domain doesnt exist (user navigated to
    # this page manually) then a not authorized page will be served. If the domain is not a valid domain (regex) the
    # request will be redirected back to blocked page without a domain. NOTE: this is a crazy bit of code that should be
    # tested much more as it is possible to do a sql injection here if the validations below are bypassed.
    blocked_domain = request.args.get('dom', None)
    if (not blocked_domain):
        session.pop('user', None)

        return render_template('main/not_authorized.html', **page_settings)

    try:
        validate.domain(blocked_domain)
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

# --------------------------------------------- #
# --------------------------------------------- #
@app.route('/', methods=['GET'])
def main():
    return redirect(url_for('dnx_login'))

# --------------------------------------------- #
# all standard page loads use this logic to decide the page action/ call the correct
# lower level functions residing in each pages Class
def standard_page_logic(dnx_page, page_settings, data_key, *, page_name):
    if (request.method == 'POST'):
        tab = request.form.get('tab', '1')

        try:
            error = dnx_page.update_page(request.form)
        except OSError as ose:
            return render_template(application_error_page, general_error=ose, **page_settings)

        page_settings.update({
            'tab': tab,
            'standard_error': error
        })

    try:
        page_settings[data_key] = dnx_page.load_page(request.form)
    except OSError as ose:
        return render_template(application_error_page, general_error=ose, **page_settings)

    return render_template(f'{page_name}.html', **page_settings)

def firewall_page_logic(dnx_page, page_settings, data_key, *, page_name):
    if (request.method == 'POST'):

        try:
            error, selected, page_data = dnx_page.update_page(request.form)
        except OSError as ose:
            return render_template(application_error_page, general_error=ose, **page_settings)

        page_settings.update({
            'tab': request.form.get('tab', '1'),
            'selected': selected,
            'standard_error': error,
            data_key: page_data
        })

    else:
        page_settings[data_key] = dnx_page.load_page()

    return render_template(f'{page_name}.html', **page_settings)

def log_page_logic(log_page, page_settings, *, page_name):
    # can now accept redirects from other places on the webui to load specific tables directly on load
    # using uri queries

    if (request.method == 'GET'):
        request_data, handler = request.args, log_page.load_page

    elif (request.method == 'POST'):
        request_data, handler = request.form, log_page.update_page

    try:
        table_data, table, menu_option = handler(request_data)
    except OSError as ose:
        return render_template(application_error_page, general_error=ose, **page_settings)

    page_settings.update({
        'table_data': table_data,
        'table': table,
        'menu': menu_option
    })

    return render_template(f'{page_name}.html', **page_settings)

def categories_page_logic(dnx_page, page_settings):
    if (request.method == 'POST'):
        try:
            error, menu_option = dnx_page.update_page(request.form)
        except OSError as ose:
            return render_template(application_error_page, general_error=ose, **page_settings)

        tab = request.form.get('tab', '1')
        menu_option = request.form.get('menu', '1')
        menu_option = int(menu_option) if menu_option.isdigit() else '1'

        page_settings.update({
            'menu': menu_option,
            'tab': tab,
            'standard_error': error
        })

    try:
        page_settings['category_settings'] = dnx_page.load_page(page_settings['menu'])
    except OSError as ose:
        return render_template(application_error_page, general_error=ose, **page_settings)

    return render_template('settings/categories.html', **page_settings)

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

        # i prefer the word restart so converting to system command here
        action = 'reboot' if action == 'restart' else f'{action} now'

        # TODO: make sure this is authenticated
        # forwarding request to system control service via local socket for execution
        system_action(delay=FIVE_SEC, module='webui', command=action)

    elif (response == 'NO'):
        return redirect(url_for('dnx_dashboard'))

    return render_template('main/device.html', **page_settings)

def update_session_tracker(username, user_role=None, remote_addr=None, *, action=CFG.ADD):

    if (action is CFG.ADD and not remote_addr):
        raise ValueError('remote_addr must be specified if action is set to add.')

    with ConfigurationManager('session_tracker', file_path='dnx_webui/data') as session_tracker:
        persistent_tracker = session_tracker.load_configuration()

        if (action is CFG.ADD):
            persistent_tracker['active_users'][username] = {
                'role': user_role,
                'remote_addr': remote_addr,
                'logged_in': time.time(),  # NOTE: can probably make this human readable format here.
                'last_seen': None
            }

        elif (action is CFG.DEL):
            persistent_tracker['active_users'].pop(username, None)

        session_tracker.write_configuration(persistent_tracker)

def ajax_response(*, status, data):
    if (not isinstance(status, bool)):
        raise TypeError('Ajax response status must be a boolean.')

    return jsonify({'success': status, 'result': data})

# =================================
# FLASK API - REQUEST MODS
# =================================
@app.before_request
def user_timeout():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

# checks form data for a color mode change and writes/ configures accordingly. otherwise will load
# the current dark mode setting for the active user and set flask.session['dark_mode] accordingly.
@app.before_request
def dark_mode():
    '''
    the configured value will be stored as session['dark_mode'] so it can be accessed directly by the
    Flask template context.
    '''
    # dark mode settings will only apply to logged in users.
    # NOTE: username validations are still required lower down to deal with log in/out transitions.
    user = session.get('user', None)
    if (not user):
        return

    dark_mode_update = request.args.get('dark_mode_update', DATA.MISSING)
    # this ensures value conforms to system before configuring
    if (dark_mode_update is not DATA.MISSING):
        try:
            dark_mode = CFG(validate.convert_int(dark_mode_update))
        except:
            return

        with ConfigurationManager('logins', file_path='/dnx_webui/data') as webui:
            webui_settings = webui.load_configuration()

            active_users = webui_settings['users']

            # this check prevents issues with log in/out transitions
            if (user not in active_users):
                return

            active_users[user]['dark_mode'] = dark_mode

            webui.write_configuration(webui_settings)

    # standard request for page. did NOT submit dark mode fab.
    else:
        webui_settings = load_configuration('logins', filepath='dnx_webui/data')

        # this check prevents issues with log in/out transitions
        user = webui_settings['users'].get(user)
        if (not user):
            return

        dark_mode = user['dark_mode']

    session['dark_mode'] = dark_mode

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
    properties = {'country': ['red', 'language'], 'address': ['blue lighten-2', 'tv'], 'service': ['orange lighten-2', 'track_changes']}.get(fw_obj[3], ['', ''])

    return (f'<div class="chip tooltipped {properties[0]}" data-html="true"'
                f'data-tooltip="<p style=width:160px> {fw_obj[2]}<br>{fw_obj[3]}<br>{fw_obj[4]}<br>{fw_obj[5]}</p>">'
                f'<i class="material-icons tiny {properties[0]} valign-center">{properties[1]}</i> <big>{fw_obj[1]}</big>'
             '</div>')

def is_list(li, /):
    return isinstance(li, list)

def _debug(obj, /):
    print(obj)


app.add_template_global(merge_items, name='merge_items')
app.add_template_global(format_fw_obj, name='format_fw_obj')
app.add_template_global(is_list, name='is_list')
app.add_template_global(_debug, name='debug')

if __name__ == '__main__':
    app.run(debug=True)
