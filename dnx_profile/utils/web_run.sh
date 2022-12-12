#!/bin/bash

# LABEL: DEVELOPMENT_ONLY_CODE

export HOME_DIR=/home/$USER/dnxfirewall
export WEB_DIR=$HOME_DIR/dnx_webui
export FLASK_DIR=$HOME_DIR/dnx_webui
export FLASK_APP=$FLASK_DIR
export FLASK_ENV=development
export PYTHONPATH=$HOME_DIR:$FLASK_DIR:$PYTHONPATH
export INIT=1
export webui=1

ip_addrs=($(hostname -I | tr " " "\n" | grep -E '192|172'))

flask run --host=${ip_addrs[0]} --port=$1