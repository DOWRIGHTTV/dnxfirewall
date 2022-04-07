#!/bin/bash

export HOME_DIR=/home/free/Desktop/new_repos/dnxfirewall-cmd
export FLASK_DIR=$HOME_DIR/dnx_webui
export FLASK_APP=$FLASK_DIR/source/main/dfe_main.py
export FLASK_ENV=development
export PYTHONPATH=$HOME_DIR:$FLASK_DIR:$PYTHONPATH

flask run --host=192.168.5.179 --port="$1"
