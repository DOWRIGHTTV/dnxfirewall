from __future__ import annotations

# =================================
# LABEL: DEVELOPMENT_ONLY_CODE
# =================================
from dnx_gentools.def_constants import ppt, WEBUI_DEVELOPMENT

from source.main.dfe_main import app

from flask import request

# =================================
# DECORATORS AND DEV HELPERS
# =================================
def noop(*args, **kwargs):
    return None

def dev_before_request(function_to_register):
    if (WEBUI_DEVELOPMENT): app.before_request(function_to_register)
    return noop

def dev_after_request(function_to_register):
    if (WEBUI_DEVELOPMENT): app.after_request(function_to_register)
    return noop

# =================================
# FLASK REQUEST HOOKS
# =================================
# will only be registered if running on dev branch using flask dev server
@dev_before_request
def print_forms() -> None:
    if (request.method != 'POST'):
        return None

    print(f'{"=" * 16}\nform data\n{"=" * 16}')
    if ajax_data := request.get_json(silent=True):
        ppt(ajax_data)

    elif form_data := dict(request.form):

        if private_data := form_data.pop('password', ''):
            form_data['password'] = '*' * len(private_data)

        ppt(form_data)

    else: print('[no data]')

@dev_after_request
def no_store_http_header(response):
    # matches primary html files only
    if ('.' not in request.path):
        response.headers.add('Cache-Control', 'no-store')

    return response
