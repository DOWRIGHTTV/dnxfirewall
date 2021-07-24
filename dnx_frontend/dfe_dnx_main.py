#!/usr/bin/env python3

import json
import hashlib
import os, sys
import time
import threading

from datetime import timedelta
from flask import Flask, render_template, redirect, url_for, request, session

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import CFG
from dnx_configure.dnx_file_operations import load_configuration, ConfigurationManager
from dnx_configure.dnx_exceptions import ValidationError
from dnx_database.ddb_connector_sqlite import DBConnector
from dnx_configure.dnx_system_info import System
from dnx_logging.log_main import LogHandler as Log

from dnx_frontend.dfe_dnx_authentication import Authentication, user_restrict

import dnx_frontend.dfe_dnx_dashboard as dfe_dashboard
import dnx_frontend.dfe_settings_dns as dns_settings
import dnx_frontend.dfe_settings_dhcp as dhcp_settings
import dnx_frontend.dfe_settings_interface as interface_settings
import dnx_frontend.dfe_settings_logging as logging_settings
import dnx_frontend.dfe_settings_syslog as syslog_settings
import dnx_frontend.dfe_settings_categories as category_settings
import dnx_frontend.dfe_advanced_whitelist as whitelist
import dnx_frontend.dfe_advanced_blacklist as blacklist
import dnx_frontend.dfe_advanced_domain as dns_proxy
import dnx_frontend.dfe_advanced_ip as ip_proxy
import dnx_frontend.dfe_advanced_firewall as dnx_firewall
import dnx_frontend.dfe_advanced_ips as dnx_ips
import dnx_frontend.dfe_system_users as dfe_users
import dnx_frontend.dfe_system_backups as dfe_backups
import dnx_frontend.dfe_system_reports as proxy_reports
import dnx_frontend.dfe_system_logs as dfe_logs
import dnx_frontend.dfe_system_services as dnx_services

LOG_NAME = 'web_app'

app = Flask(__name__, static_url_path='/static')

flask_config = load_configuration('config.json')['settings']['flask']
app.secret_key = flask_config.get('key')

trusted_proxies = ['127.0.0.1']

## ---------------------------------------------
## START OF NAVIGATION TABS
## ---------------------------------------------

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

## ---------------------------------------------
## START OF SETTINGS TAB
## ---------------------------------------------

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

    settings = category_settings.load_page(menu_option)

    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'cat_settings': True, 'tab': tab, 'menu': menu_option,
        'category_settings': settings,
        'uri_path': ['settings', 'categories']
    }

    page_settings.update(dnx_session_data)

    page_action = categories_page_logic(category_settings.update_page, page_settings)

    return page_action

## ---------------------------------------------
## START OF ADVANCED TAB
## ---------------------------------------------

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
    menu_option = request.args.get('menu', '1')

    page_settings = {
        'navi': True, 'idle_timeout': True, 'standard_error': None,
        'tab': tab, 'menu': menu_option,
        'selected': 'GLOBAL_INTERFACE',
        'zones': ['GLOBAL', 'WAN', 'DMZ', 'LAN'],
        'uri_path': ['advanced', 'firewall']
    }

    page_settings.update(dnx_session_data)

    page_action = firewall_page_logic(
        dnx_firewall, page_settings, 'firewall_settings', page_name='advanced_firewall')

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

## ---------------------------------------------
## START OF SYSTEMS TAB
## ---------------------------------------------

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

@app.route('/system/reports', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_reports(dnx_session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1', 'table': '1',
        'uri_path': ['system', 'reports']
    }

    page_settings.update(dnx_session_data)

    page_action = log_page_logic(proxy_reports, page_settings, page_name='system_reports')

    return page_action

@app.route('/system/logs', methods=['GET', 'POST'])
@user_restrict('user', 'admin')
def system_logs(dnx_session_data):
    page_settings = {
        'navi': True, 'idle_timeout': True, 'log_timeout': True, 'standard_error': None,
        'menu': '1',
        'log_files': ['combined', 'logins', 'web_app', 'system', 'dns_proxy', 'ip_proxy', 'ips', 'dhcp_server', 'syslog'],
        'uri_path': ['system', 'logs']
    }

    page_settings.update(dnx_session_data)

    page_action = log_page_logic(dfe_logs, page_settings, page_name='system_logs')

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

## ---------------------------------------------
## START OF DEVICE TAB
## ---------------------------------------------

@app.route('/device/restart', methods=['GET', 'POST'])
@user_restrict('admin')
def system_restart(dnx_session_data):
    page_settings = {
        'navi':True, 'idle_timeout': False,
        'control': True, 'action': 'restart'
    }

    page_settings.update(dnx_session_data)

    system_action = handle_system_action(page_settings)

    return system_action

@app.route('/device/shutdown', methods=['GET', 'POST'])
@user_restrict('admin')
def system_shutdown(dnx_session_data):
    page_settings = {
        'navi': True, 'idle_timeout': False,
        'control': True, 'action': 'shutdown'
    }

    page_settings.update(dnx_session_data)

    system_action = handle_system_action(page_settings)

    return system_action

## ---------------------------------------------
## START OF LOGOUT TAB
## ---------------------------------------------

@app.route('/logout', methods=['GET'])
@user_restrict('user', 'admin')
# removing user from session dict then removing them from locally stored session tracker to allow
# for cross session awareness of users/accts logged in.
def dnx_logout(dnx_session_data):
    username = session.pop('username', None)
    if (username):
        update_session_tracker(username, action=CFG.DEL)

    return redirect(url_for('dnx_login'))

## ---------------------------------------------
## BLOCKED PAGE | dns redirect
## ---------------------------------------------

@app.route('/blocked')
def dnx_blocked():
    page_settings = {'navi': True, 'login_btn': True, 'idle_timeout': False}

    # checking for domain sent by nginx that is being redirected to firewall. if domain doesnt exist (user navigated to
    # this page manually) then a not authorized page will be served. If the domain is not a valid domain (regex) the request
    # will be ridirected back to blocked page without a domain. NOTE: this is a crazy bit of code that should be tested much
    # more as it is possible to do a sql injection here if the validations below are bypassed.
    blocked_domain = request.args.get('dom', None)
    if (not blocked_domain):
        session.pop('username', None)

        return render_template('dnx_not_authorized.html', **page_settings)

    try:
        validate.domain(blocked_domain)
    except ValidationError:
        session.pop('username', None)

        return render_template('dnx_not_authorized.html', **page_settings)

    with DBConnector() as ProxyDB:
        domain_info = ProxyDB.query_blocked(domain=blocked_domain, src_ip=request.remote_addr)

    if (not domain_info):
        session.pop('username', None)

        return render_template('dnx_not_authorized.html', **page_settings)

    page_settings.update({
        'standard_error': False, 'src_ip': request.remote_addr, 'blocked': domain_info
    })

    return render_template('dnx_blocked.html', **page_settings)

## --------------------------------------------- ##
## --------------------------------------------- ##

@app.route('/login', methods=['GET', 'POST'])
# TODO: see about making session username a list of username and role so we wont have to have a separate
# role check every time the user logs in, out, or navigates to new page.
# TODO: if user is already logged in... <--- what is this???
def dnx_login():
    login_error = None
    if (request.method == 'POST'):
        authenticated, username, user_role = Authentication.user_login(request.form, request.remote_addr)
        if (authenticated):
            session['username'] = username
            # session['expire_time'] = time.time() + 30

            update_session_tracker(username, user_role, request.remote_addr)

            return redirect(url_for('dnx_dashboard'))

        login_error = 'Invalid Credentials. Please try again.'

    return render_template('dnx_login.html', navi=True, login_btn=False, idle_timeout=False,
        standard_error=False, login_error=login_error, uri_path=['login'])

# @app.route('/license_agreement', methods=['GET', 'POST'])
# @user_restrict('user', 'admin')
# def license_agreement(dnx_session_data):
#     page_settings = {
#         'navi': True, 'idle_timeout': False
#     }

#     page_settings.update(dnx_session_data)

#     return render_template('license_agreement.html', **page_settings)

## --------------------------------------------- ##
## --------------------------------------------- ##
@app.route('/', methods=['GET'])
def main():
    return redirect(url_for('dnx_login'))

## --------------------------------------------- ##
# all standard page loads use this logic to decide the page action/ call the correct
# lower level functions residing in each pages Class
def standard_page_logic(dnx_page, page_settings, data_key, *, page_name):
    if (request.method == 'POST' and 'extend_session_timer' not in request.form):
        tab = request.form.get('tab', '1')

        error = dnx_page.update_page(request.form)
        if (not error):
            return redirect(url_for(page_name, tab=tab))

        page_settings.update({
            'tab': tab,
            'standard_error': error
        })

    page_settings[data_key] = dnx_page.load_page()

    return render_template(f'{page_name}.html', **page_settings)

def firewall_page_logic(dnx_page, page_settings, data_key, *, page_name):
    if (request.method == 'POST' and 'extend_session_timer' not in request.form):
        tab = request.form.get('tab', '1')

        error, selected, page_data = dnx_page.update_page(request.form)

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
        table_data, menu_option, table = log_page.load_page(request.args)

    elif (request.method == 'POST'):
        table_data, menu_option, table = log_page.update_page(request.form)

    page_settings.update({
        'table_data': table_data,
        'menu': menu_option,
        'table': table
    })

    return render_template(f'{page_name}.html', **page_settings)

def categories_page_logic(update_page, page_settings):
    if (request.method == 'POST'):
        error, menu_option = update_page(request.form)

        tab = request.form.get('tab', '1')
        menu_option = request.form.get('menu', '1')
        menu_option = int(menu_option) if menu_option.isdigit() else '1'

        if (not error):
            return redirect(url_for('settings_categories', tab=tab, menu=menu_option))

        page_settings.update({
            'menu': menu_option,
            'standard_error': error
        })

    return render_template('settings_categories.html', **page_settings)

#function called by restart/shutdown pages. will ensure the user specified operation gets executed
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

        system_action_method = getattr(System, action)
        threading.Thread(target=system_action_method).start()

    elif (response == 'NO'):
        return redirect(url_for('dnx_dashboard'))

    return render_template('dnx_device.html', **page_settings)

def update_session_tracker(username, user_role=None, remote_addr=None, *, action=CFG.ADD):
    if (action is CFG.ADD and not remote_addr):
        raise ValueError('remote_addr must be specified if action is set to add.')

    with ConfigurationManager('session_tracker', file_path='dnx_frontend/data') as session_tracker:
        stored_tracker = session_tracker.load_configuration()

        if (action is CFG.ADD):
            stored_tracker['active_users'][username] = {
                'user_role': user_role,
                'remote_addr': remote_addr,
                'logged_in': time.time(), # NOTE: can probably make this human readable format here.
                'last_seen': None
            }

        elif (action is CFG.DEL):
            stored_tracker['active_users'].pop(username, None)

        session_tracker.write_configuration(stored_tracker)

@app.before_request
def user_timeout():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

## SETUP LOGGING CLASS
Log.run(name=LOG_NAME)

if __name__ == '__main__':
   app.run(debug=True)
