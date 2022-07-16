#!/bin/bash

export HOME_DIR=/home/free/dnxfirewall
export WEB_DIR=$HOME_DIR/dnx_webui
export FLASK_DIR=$HOME_DIR/dnx_webui
export FLASK_APP=$FLASK_DIR
export FLASK_ENV=development
export PYTHONPATH=$HOME_DIR:$FLASK_DIR:$PYTHONPATH
export INIT=1
export webui=1

flask run --host="$1" --port="$2"