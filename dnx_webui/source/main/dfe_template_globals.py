#!/usr/bin/env python3

from flask import Flask, g as context_global

app = Flask.app

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