#!/bin/bash

export HOME_DIR=/home/$USER/dnxfirewall
export WEB_DIR=$HOME_DIR/dnx_webui
export FLASK_DIR=$HOME_DIR/dnx_webui
export FLASK_APP=$FLASK_DIR
export FLASK_ENV=development
export PYTHONPATH=$HOME_DIR:$FLASK_DIR:$PYTHONPATH
export INIT=1
export webui=1

flask run --host="$(hostname -I)" --port="$1"