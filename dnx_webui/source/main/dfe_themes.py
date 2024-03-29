#!/usr/bin/env python3

from flask import Flask, g as context_global

app = Flask.app

# ================
# THEMES
# ================
# string helpers
bg_setting = ' background-repeat: repeat; background-attachment: fixed;'

theme_common = {
    'mode': '',
    'nav_text': 'blue-grey-text text-darken-2',
    'subnav_text': 'blue-grey-text text-darken-3',
    'tab_text': 'blue-grey-text text-lighten-2',
    'tab_classes': 'tab col s4 l3 xl2',
    'icon': 'teal-text text-lighten-2',
    'modal_text': 'blue-grey-text center',
}

theme_dark = {
    'main_bg': 'background: url(static/assets/images/dnx_bg1_dark.svg);' + bg_setting,
    'main_section': 'blue-grey lighten-2',
    'off_bg': 'background: url(static/assets/images/dnx_bg1_light.svg);' + bg_setting,
    'off_section': 'blue-grey lighten-5',
    'card': 'blue-grey lighten-4',
    'title': 'black-text'
}

theme_light = {
    'main_bg': 'background: url(static/assets/images/dnx_bg1_light.svg);' + bg_setting,
    'main_section': 'grey lighten-2',
    'off_bg': 'background: url(static/assets/images/dnx_bg1_dark.svg);' + bg_setting,
    'off_section': 'grey lighten-5',
    'card': 'grey lighten-4',
    'title': 'blue-grey-text text-darken-1'
}

@app.before_request
def set_theme_values() -> None:
    style = context_global.settings['theme']

    context_global.theme = {'mode': style}
    context_global.theme.update(theme_common)

    if (style == 'dark'):
        context_global.theme.update(theme_dark)

    elif (style == 'light'):
        context_global.theme.update(theme_light)