#!/bin/bash

# LABEL: DEVELOPMENT_ONLY_CODE

# PATH AND DIRECTORY SETUP
export HOME_DIR=/home/$USER/dnxfirewall
export WEB_DIR=$HOME_DIR/dnx_webui
export PYTHONPATH=$HOME_DIR:$FLASK_DIR:$PYTHONPATH

# FLASK SETUP
export FLASK_DIR=$HOME_DIR/dnx_webui
export FLASK_APP=$FLASK_DIR
export FLASK_ENV=development

# WEBUI DEVELOPMENT FLAGS
export INIT=1 # required to run in cli
export WEBUI_DEVELOPMENT=1

# RUN COMMANDS
# filter out loopback and public ip addresses.
ip_addrs=($(hostname -I | tr " " "\n" | grep -E '192.|10.|172.'))

# selecting the first available local ip address
flask run --host=${ip_addrs[0]} --port=$1