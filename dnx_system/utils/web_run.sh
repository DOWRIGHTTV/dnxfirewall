#!/bin/bash

export FLASK_APP=/home/free/Desktop/new_repos/dnxfirewall-cmd/dnx_webui/source/main/dfe_main.py
export FLASK_ENV=development
export PYTHONPATH=/home/free/Desktop/new_repos/dnxfirewall-cmd/dnx_webui:$PYTHONPATH
export HOME_DIR=/home/free/Desktop/new_repos/dnxfirewall-cmd
flask run --host=192.168.5.179 --port="$1"
