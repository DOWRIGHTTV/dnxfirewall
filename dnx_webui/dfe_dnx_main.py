#!/usr/bin/env python3

# for running with flask dev server
if (__name__ == '__main__'):
    import __init__

import time

from datetime import timedelta
from flask import Flask, render_template, redirect, url_for, request, session, jsonify

import dnx_routines.configure.web_validate as validate

from dnx_gentools.def_constants import CFG, DATA, FIVE_SEC
from dnx_gentools.file_operations import load_configuration, ConfigurationManager
from dnx_routines.configure.exceptions import ValidationError
from dnx_routines.database.ddb_connector_sqlite import DBConnector
from dnx_routines.logging.log_main import LogHandler as Log

import dnx_webui.dfe_dnx_dashboard as dfe_dashboard
import dnx_webui.dfe_settings_dns as dns_settings
import dnx_webui.dfe_settings_dhcp as dhcp_settings
import dnx_webui.dfe_settings_interface as interface_settings
import dnx_webui.dfe_settings_logging as logging_settings
import dnx_webui.dfe_settings_syslog as syslog_settings
import dnx_webui.dfe_settings_categories as category_settings
import dnx_webui.dfe_advanced_whitelist as whitelist
import dnx_webui.dfe_advanced_blacklist as blacklist
import dnx_webui.dfe_advanced_firewall as dnx_fwall
import dnx_webui.dfe_advanced_nat as dnx_nat
import dnx_webui.dfe_advanced_domain as dns_proxy
import dnx_webui.dfe_advanced_ip as ip_proxy
import dnx_webui.dfe_advanced_ips as dnx_ips
import dnx_webui.dfe_system_logs as dfe_logs
import dnx_webui.dfe_system_reports as proxy_reports
import dnx_webui.dfe_system_users as dfe_users
import dnx_webui.dfe_system_backups as dfe_backups
import dnx_webui.dfe_system_services as dnx_services

from dnx_webui.dfe_dnx_authentication import Authentication, user_restrict

from dnx_system.sys_main import system_action
from dnx_secmods.cfirewall.fw_manage import FirewallManage

LOG_NAME = 'web_app'

app = Flask(__name__, static_url_path='/static')

# a new key is generated on every system start and stored in system config.
app.secret_key = load_configuration('config')['flask'].get('key')

trusted_proxies = ['127.0.0.1']

# setup for system logging
Log = Log.run(name=LOG_NAME)

# initialize cfirewall manager, which interfaces with cfirewall control class through a fd.
cfirewall = FirewallManage()

# setting ref class var to instance. this will allow any webui module to access firewall
# state without passing around object.
FirewallManage.cfirewall = cfirewall

# NOTE: this will allow the config manager to reference the Log class without an import. (cyclical import error)
ConfigurationManager.set_log_reference(Log)

# --------------------------------------------- #
#  START OF NAVIGATION TABS
# --------------------------------------------- #

# TODO: figure out best visually pleasing way to inject current logged in user info on each page.
@app.route('/dashboard', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def dnx_dashboard(dnx_session_data):
    dashboard = dfe_dashboard.load_page()

    page_settings = {
        'navi': True, 'footer': True, 'standard_error': False,
        'idle_timeout': True, 'dashboard': dashboard,
        'uri_path': ['dashboard',]
    }

    page_settings.update(dnx_session_data)

    return render_template('dnx_dashboard.html', **page_settings)

# --------------------------------------------- #
#  START OF SETTINGS TAB
# --------------------------------------------- #

@app.route('/settings/dns', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_dns(dnx_session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['settings', 'dns']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        dns_settings, page_settings, 'dns_settings' , page_name='settings_dns')

    return page_action

@app.route('/settings/dhcp', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_dhcp(dnx_session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['settings', 'dhcp']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        dhcp_settings, page_settings, 'dhcp_settings' , page_name='settings_dhcp')

    return page_action

@app.route('/settings/interface', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_interface(dnx_session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['settings', 'interface']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        interface_settings, page_settings, 'interface_settings', page_name='settings_interface')

    return page_action

@app.route('/settings/logging', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_logging(dnx_session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['settings', 'logging']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        logging_settings, page_settings, 'logging_settings', page_name='settings_logging')

    return page_action

@app.route('/settings/syslog', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_syslog(dnx_session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['settings', 'syslog']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        syslog_settings, page_settings, 'syslog_settings', page_name='settings_syslog')

    return page_action

@app.route('/settings/categories', methods=['GET', 'POST'])
@user_restrict('admin')
def settings_categories(dnx_session_data):
    tab = request.args.get('tab', '1')
    menu_option = request.args.get('menu', '1')
    menu_option = int(menu_option) if menu_option.isdigit() else '1'

    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'cat_settings': True, 'tab': tab, 'menu': menu_option,
        'uri_path': ['settings', 'categories']
    }

    page_settings.update(dnx_session_data)

    page_action = categories_page_logic(category_settings, page_settings)

    return page_action

# --------------------------------------------- #
#  START OF ADVANCED TAB
# --------------------------------------------- #

@app.route('/advanced/whitelist', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_whitelist(dnx_session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['advanced', 'whitelist']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        whitelist, page_settings, 'whitelist_settings', page_name='advanced_whitelist')

    return page_action

@app.route('/advanced/blacklist', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_blacklist(dnx_session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['advanced', 'blacklist']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        blacklist, page_settings, 'blacklist_settings', page_name='advanced_blacklist')

    return page_action

@app.route('/advanced/firewall', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_firewall(dnx_session_data):
    tab = request.args.get('tab', '1')

    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'dnx_table': True, 'firewall': True,
        'geolocation': True,
        'selected': 'MAIN',
        'sections': ['BEFORE', 'MAIN', 'AFTER'],
        'uri_path': ['advanced', 'firewall']
    }

    page_settings.update(dnx_session_data)

    page_action = firewall_page_logic(
        dnx_fwall, page_settings, 'firewall_settings', page_name='advanced_firewall')

    return page_action

@app.route('/advanced/nat', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_nat(dnx_session_data):
    tab = request.args.get('tab', '1')
    menu_option = request.args.get('menu', '1')

    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'menu': menu_option,
        'selected': 'WAN_ZONE',
        'zones': ['WAN', 'DMZ', 'LAN'],
        'uri_path': ['advanced', 'nat']
    }

    page_settings.update(dnx_session_data)

    page_action = firewall_page_logic(
        dnx_nat, page_settings, 'nat_settings', page_name='advanced_nat')

    return page_action

@app.route('/advanced/domain', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_domain(dnx_session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['advanced', 'domain']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        dns_proxy, page_settings, 'domain_settings', page_name='advanced_domain')

    return page_action

@app.route('/advanced/ip', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_ip(dnx_session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['advanced', 'ip']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        ip_proxy, page_settings, 'ip_settings', page_name='advanced_ip')

    return page_action

@app.route('/advanced/ips', methods=['GET', 'POST'])
@user_restrict('admin')
def advanced_ips(dnx_session_data):
    tab = request.args.get('tab', '1')
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'uri_path': ['advanced', 'ips']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        dnx_ips, page_settings, 'ips_settings', page_name='advanced_ips')

    return page_action

# --------------------------------------------- #
#  START OF SYSTEMS TAB
# --------------------------------------------- #

@app.route('/system/logs', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_logs(dnx_session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'dnx_table': True, 'ajax': True, 'auto_colorize': True,
        'log_files': [
            'combined', 'logins', 'web_app', 'system', 'dns_proxy', 'ip_proxy', 'ips', 'dhcp_server', 'syslog'
        ],
        'uri_path': ['system', 'logs']
    }

    page_settings.update(dnx_session_data)

    page_action = log_page_logic(dfe_logs, page_settings, page_name='system_logs')

    return page_action

@app.route('/system/logs/get', methods=['POST',])
@user_restrict('user', 'admin')
def system_logs_get(dnx_session_data):
    json_data = request.get_json(force=True)

    table_data, _, _ = dfe_logs.update_page(json_data)

    return ajax_response(status=True, data=table_data)

@app.route('/system/reports', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_reports(dnx_session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'table': '1', 'dnx_table': True, 'ajax': False, 'auto_colorize': True,
        'uri_path': ['system', 'reports'],
        'table_types': ['dns_proxy', 'ip_proxy', 'intrusion_prevention', 'infected_clients']
    }

    page_settings.update(dnx_session_data)

    page_action = log_page_logic(proxy_reports, page_settings, page_name='system_reports')

    return page_action

@app.route('/system/users', methods=['GET', 'POST'])
@user_restrict('admin')
def system_users(dnx_session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'uri_path': ['system', 'users']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        dfe_users, page_settings, 'user_list', page_name='system_users')

    return page_action

@app.route('/system/backups', methods=['GET', 'POST'])
@user_restrict('admin')
def system_backups(dnx_session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'uri_path': ['system', 'backups']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        dfe_backups, page_settings, 'current_backups', page_name='system_backups')

    return page_action

@app.route('/system/services', methods=['GET', 'POST'])
@user_restrict('admin')
def system_services(dnx_session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'uri_path': ['system', 'services']
    }

    page_settings.update(dnx_session_data)

    page_action = standard_page_logic(
        dnx_services, page_settings, 'service_info', page_name='system_services')

    return page_action

# --------------------------------------------- #
#  START OF DEVICE TAB
# --------------------------------------------- #

@app.route('/device/restart', methods=['GET', 'POST'])
@user_restrict('admin')
def system_restart(dnx_session_data):
    page_settings = {
        'navi': True, 'idle_timeout': False,
        'control': True, 'action': 'restart',
        'uri_path': ['device', 'restart']
    }

    page_settings.update(dnx_session_data)

    system_action = handle_system_action(page_settings)

    return system_action

@app.route('/device/shutdown', methods=['GET', 'POST'])
@user_restrict('admin')
def system_shutdown(dnx_session_data):
    page_settings = {
        'navi': True, 'idle_timeout': False,
        'control': True, 'action': 'shutdown',
        'uri_path': ['device', 'shutdown']
    }

    page_settings.update(dnx_session_data)

    system_action = handle_system_action(page_settings)

    return system_action

# --------------------------------------------- #
#  START OF LOGOUT TAB
# --------------------------------------------- #

@app.route('/logout', methods=['GET'])
@user_restrict('user', 'admin')
# removing user from session dict then removing them from locally stored session tracker to allow
# for cross session awareness of users/accts logged in.
def dnx_logout(dnx_session_data):
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

        return render_template('dnx_not_authorized.html', **page_settings)

    try:
        validate.domain(blocked_domain)
    except ValidationError:
        session.pop('user', None)

        return render_template('dnx_not_authorized.html', **page_settings)

    with DBConnector() as firewall_db:
        domain_info = firewall_db.execute('blocked_domain', domain=blocked_domain, src_ip=request.remote_addr)

    if (not domain_info):
        session.pop('user', None)

        return render_template('dnx_not_authorized.html', **page_settings)

    page_settings.update({
        'standard_error': False, 'src_ip': request.remote_addr, 'blocked': domain_info
    })

    return render_template('dnx_blocked.html', **page_settings)

# --------------------------------------------- #
# --------------------------------------------- #

@app.route('/login', methods=['GET', 'POST'])
def dnx_login():

    # user already has an active authenticated session so we can just drop them back to the dashboard.
    if (session.get('user', None)):
        return redirect(url_for('dnx_dashboard'))

    login_error = None
    if (request.method == 'POST'):
        authenticated, username, user_role = Authentication.user_login(request.form, request.remote_addr)
        if (authenticated):
            session['user'] = {
                'name': username, 'role': user_role, 'remote_addr': request.remote_addr, 'dark_mode': 0
            }

            update_session_tracker(username, user_role, request.remote_addr)

            return redirect(url_for('dnx_dashboard'))

        login_error = 'Invalid Credentials. Please try again.'

    return render_template(
        'dnx_login.html', navi=False, login_btn=False, idle_timeout=False,
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
            return render_template(f'dnx_general_error.html', general_error=ose, **page_settings)

        page_settings.update({
            'tab': tab,
            'standard_error': error
        })

    try:
        page_settings[data_key] = dnx_page.load_page(request.form)
    except OSError as ose:
            return render_template(f'dnx_general_error.html', general_error=ose, **page_settings)

    return render_template(f'{page_name}.html', **page_settings)

def firewall_page_logic(dnx_page, page_settings, data_key, *, page_name):
    if (request.method == 'POST'):
        tab = request.form.get('tab', '1')

        try:
            error, selected, page_data = dnx_page.update_page(request.form)
        except OSError as ose:
            return render_template(f'dnx_general_error.html', general_error=ose, **page_settings)

        page_settings.update({
            'tab': tab,
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
        return render_template(f'dnx_general_error.html', general_error=ose, **page_settings)

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
            return render_template(f'dnx_general_error.html', general_error=ose, **page_settings)

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
        return render_template(f'dnx_general_error.html', general_error=ose, **page_settings)

    return render_template('settings_categories.html', **page_settings)

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

    return render_template('dnx_device.html', **page_settings)

def update_session_tracker(username, user_role=None, remote_addr=None, *, action=CFG.ADD):

    if (action is CFG.ADD and not remote_addr):
        raise ValueError('remote_addr must be specified if action is set to add.')

    with ConfigurationManager('session_tracker', file_path='dnx_webui/data') as session_tracker:
        stored_tracker = session_tracker.load_configuration()

        if (action is CFG.ADD):
            stored_tracker['active_users'][username] = {
                'role': user_role,
                'remote_addr': remote_addr,
                'logged_in': time.time(), # NOTE: can probably make this human readable format here.
                'last_seen': None
            }

        elif (action is CFG.DEL):
            stored_tracker['active_users'].pop(username, None)

        session_tracker.write_configuration(stored_tracker)

def ajax_response(*, status, data):
    if (not isinstance(status, bool)):
        raise TypeError('Ajax response status must be a boolean.')

    return jsonify({'success': status, 'result': data})

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
    # this ensure value conforms to system before configuring
    if (dark_mode_update is not DATA.MISSING):
        try:
            dark_mode = CFG(validate.convert_int(dark_mode_update))
        except:
            return

        with ConfigurationManager('logins', file_path='/dnx_webui/data') as webui:
            webui_settings = webui.load_configuration()

            active_users = webui_settings['users']

            # this check prevents issues with log in/out transitions
            if (user['name'] not in active_users):
                return

            active_users[user['name']]['dark_mode'] = dark_mode

            webui.write_configuration(webui_settings)

    # standard request for page. did NOT submit dark mode fab.
    else:
        webui_settings = load_configuration('logins', filepath='dnx_webui/data')

        # this check prevents issues with log in/out transitions
        user = webui_settings['users'].get(user['name'])
        if (not user):
            return

        dark_mode = user['dark_mode']

    session['dark_mode'] = dark_mode

@app.before_request
def user_timeout():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

# jinja filters
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

app.add_template_global(merge_items, name='merge_items')

if __name__ == '__main__':
    app.run(debug=True)
