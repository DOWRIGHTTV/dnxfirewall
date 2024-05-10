#!/usr/bin/env python3

from __future__ import annotations

from flask import Flask, g as context_global

app = Flask.app

# ====================================
# FLASK API - TEMPLATE FUNCTIONS
# ====================================
@app.template_global()
def create_title(title: str, classes: str = '') -> str:
    classes = 'card-title ' + classes

    return (
        f'<div class="row"><h5 class="{context_global.theme["title"]} {classes}">{title.title()}</h5></div>'
        f'<div class="title-divider"></div><br>'
    )

@app.template_global()
def create_switch(label: str, name: str, *, tab: int = 1, checked: int = 0, enabled: int = 1) -> str:
    if (not enabled): status = 'disabled'
    elif (checked): status = 'checked'
    else: status = ''

    return ''.join([
        f'<form method="post"><input type="hidden" name="tab" value="{tab}">',
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
        classes: str, icon: str, modal_idx: int, iter: int, tab: int, btn_name: str, btn_value: str, message: str) -> str:

    btn_classes = f'{classes} waves-effect waves-light modal-trigger'

    # hidden input for button value is to add forward compatibility with the new form validation system

    button = (
        f'<a class="{btn_classes}" href="#modal{modal_idx}-{iter}"><i class="material-icons">{icon}</i></a>'
        f'<div id="modal{modal_idx}-{iter}" class="modal">'
          f'<div class="modal-content"><h5 class="{context_global.theme["modal_text"]}">{message}</h5></div>'
          f'<form method="POST">'
            f'<input type="hidden" name="tab" value="{tab}">'
            f'<input type="hidden" name="{btn_name}" value="{btn_value}">'
            '<div class="modal-footer">'
              f'<button name="vbtn" value="{btn_name}" class="btn waves-effect waves-light">YES</button>'
              '<a class="modal-close waves-effect waves-green btn-flat">Cancel</a>'
            '</div>'
          '</form>'
        '</div>'
    )

    return button

@app.template_global()
def create_decora_switch(name: str, value: str, checked: int, *, enabled: int = 1, onclick: str = 'updateCategory'):
    '''generates and returns HTML containing a title and a single decora switches.
    '''
    disabled = ' disabled' if not enabled else ''
    off = ' active' if (not checked or disabled) else ''
    on  = ' active' if (checked and not disabled) else ''

    switch = (
        f'<div class="col s3"><div class="row row-thin"><p class="multi-switch-label center">{value.replace("_", " ")}</p></div>'
        '<div class="row row-thin"><div class="multi-switch-wrapper decora-switch">'
        f'<ul class="multi-switch"{disabled}>'
            f'<li class="multi-switch-off{off}"><button name="{name}" value="{value}" onclick="{onclick}(this, 0)">'
                '<i class="material-icons small">radio_button_unchecked</i></button></li>'
            f'<li class="multi-switch-on{on}"><button name="{name}" value="{value}" onclick="{onclick}(this, 1)">'
                '<i class="material-icons small">block</i></button></li>'
        '</ul></div></div></div>'
    )

    return switch

@app.template_global()
def create_tandem_decora_switch(name: tuple[str, str], value: str, checked: tuple[int, int, int],
        *, enabled: int = 1, onclick: str = 'updateCategory'):
    '''generates and returns HTML containing a title and (2) decora switches.

    the second switch will be tethered to the first such that if the first is NOT checked, the second will be marked
    as "disabled" and unable to be submitted.
    '''

    # checked = enabled, keyword, tethered

    disabled = ' disabled' if not enabled else ''
    off = ' active' if (not checked[0] or disabled) else ''
    on  = ' active' if (checked[0] and not disabled) else ''

    # disabled_two = ' disabled' if not on else ''
    disabled_two = ' disabled' if disabled else ''
    off_two = ' active' if (not checked[1] or disabled_two) else ''
    on_two  = ' active' if (checked[1] and not disabled_two) else ''

    # switch_code_off = 0 if not checked[2] else 2
    # switch_code_on  = 1 if not checked[2] else 3
    th = 0 if not checked[2] else 1

    value_name = value.split(',')[1]

    switch = (
        '<div class="col s3 multi-switch-container">'
            f'<div class="row row-thin"><p class=" multi-switch-label center">{value_name.replace("_", " ")}</p></div>'
            '<div class="row">'
                '<h6 class="center">STANDARD</h6>'
                f'<div id="{value_name}-1" class="multi-switch-wrapper decora-switch">'
                    '<ul class="multi-switch">'
                        f'<li class="multi-switch-off{off}"><button name="{name[0]}" value="{value}" onclick="{onclick}(0,this,0,{th})"{disabled}>'
                            '<i class="material-icons small">radio_button_unchecked</i></button></li>'
                        f'<li class="multi-switch-on{on}"><button name="{name[0]}" value="{value}" onclick="{onclick}(0,this,1,{th})"{disabled}>'
                            '<i class="material-icons small">block</i></button></li>'
                    '</ul>'
                '</div>'
            '</div>'
            '<div class="row row-thin">'
                '<h6 class="center">KEYWORD</h6>'
                f'<div id="{value_name}-2" class="multi-switch-wrapper decora-switch">'
                    '<ul class="multi-switch">'
                        f'<li class="multi-switch-off{off_two}"><button name="{name[1]}" value="{value}" onclick="{onclick}(1,this,0,{th})"{disabled_two}>'
                            '<i class="material-icons small">radio_button_unchecked</i></button></li>'
                        f'<li class="multi-switch-on{on_two}"><button name="{name[1]}" value="{value}" onclick="{onclick}(1,this,1,{th})"{disabled_two}>'
                            '<i class="material-icons small">block</i></button></li>'
                    '</ul>'
                '</div>'
            '</div>'
        '</div>'
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

def _highlighter_py():

    PY_BOOL_HEX = '#477766'
    PY_CONDITIONAL_HEX = '#477766'
    PY_OPERATOR_HEX = '#e66170'
    PY_KEYWORD_HEX = '#a08050'
    PY_QUOTE_HEX = '#02d045'
    PY_STRING_HEX = '#00c4c4'

    py_bools = ['False', 'True', 'None']
    py_conditionals = ['if', 'elif', 'else']
    py_operators = [' and ', ' or ', ' not ', ' in ', ' is ']
    py_keywords = [
        ' as ', ' assert ', ' async ', ' await ', ' break ', ' class ', ' continue ',
        ' def ', ' del ', ' except ', ' finally ', ' for ', ' from ', ' global ',
        ' import ', ' lambda ', ' nonlocal ', ' pass ', ' raise ', ' return ', ' try ',
        ' while ', ' with ', ' yield '
    ]

    def highlight_html_python(s: str) -> str:
        for py_bool in py_bools:
            s = s.replace(py_bool, f'<span style="color:{PY_BOOL_HEX};">{py_bool}</span>')

        for py_conditional in py_conditionals:
            s = s.replace(py_conditional, f'<span style="color:{PY_CONDITIONAL_HEX};">{py_conditional}</span>')

        for py_operator in py_operators:
            s = s.replace(py_operator, f'<span style="color:{PY_OPERATOR_HEX};">{py_operator}</span>')

        for py_keyword in py_keywords:
            s = s.replace(py_keyword, f'<span style="color:{PY_KEYWORD_HEX};">{py_keyword}</span>')

        # STRING REPLACEMENTS
        s = s.replace(' "', f'<span style="color:{PY_QUOTE_HEX};">"</span><span style="color:{PY_STRING_HEX};">')

        for c in ['" ', '",']:
            s = s.replace(c, f'</span><span style="color:{PY_QUOTE_HEX};">{c}</span>')

        return s

    return highlight_html_python

app.add_template_global(_highlighter_py(), 'highlighter_py')

@app.template_global()
def resource_usage_bar(*, perc: float) -> str:
    '''returns a string containing HTML for a progress bar that displays the current resource usage.
    '''

    green, yellow, orange, red = '#5EC435', '#E5DF1D', '#DF921D', '#BF3535'

    if perc >= 90: bar_color = red
    elif perc >= 75: bar_color = orange
    elif perc >= 50: bar_color = yellow
    else: bar_color = green

    utilization_bar = f'''
    <svg class="svg-progress-bar">
      <svg preserveAspectRatio="none" viewBox="0 0 100 65">
        <rect class="bg" fill="#ccc" width="100%" height="90%" rx="2"></rect>
        <rect class="data" fill="{bar_color}" width="{perc}%" height="90%" rx="2"></rect>
        <g class="markers">
          <line x1="25%" y1="0" x2="25%" y2="100%"></line>
          <line x1="50%" y1="0" x2="50%" y2="100%"></line>
          <line x1="75%" y1="0" x2="75%" y2="100%"></line>
        </g>
      </svg>
      <g text-anchor="middle"><text fill="#030303" x="50%" y="65%">{perc}%</text></g>
    </svg>
    '''

    return utilization_bar
