#!/usr/bin/env python3

import os

# HOME_DIR: str = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-3]))
HOME_DIR = 'C:/Users/dowright/PycharmProjects/dnxfirewall'
CFIREWALL_DIR = f'{HOME_DIR}/dnx_secmods/cfirewall/fw_main'

os.chdir(CFIREWALL_DIR)
pxd_files = os.listdir('h_files')

with open('fw_main.pxd', 'w') as fw_main_h:
    for file in pxd_files:
        print(f'merging {file}')

        with open(f'h_files/{file}', 'r') as h_file:
            fw_main_h.write(h_file.read())
            fw_main_h.write('\n')
