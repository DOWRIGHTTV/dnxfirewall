#!/bin/bash

export FLASK_APP=/home/free/Desktop/new_repos/dnxfirewall-cmd/dnx_frontend/dfe_dnx_main.py
export FLASK_ENV=development
export HOME_DIR=/home/free/Desktop/new_repos/dnxfirewall-cmd
flask run --host=192.168.5.179 --port=$1
