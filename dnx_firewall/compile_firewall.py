#!/usr/bin/env python3

import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

os.chdir('/home/free/Desktop/new_repos/dnxfirewall-cmd/dnx_firewall')

#os.chdir('/home/dnx/dnxfirewall/dnx_firewall')

cmd = {'build_ext': build_ext}
ext = Extension(
    'fw_main', sources=['fw_main.pyx'], libraries=['netfilter_queue']
)

setup(
    name='DNXFIREWALL', cmdclass=cmd, ext_modules=cythonize(ext, language_level='3')
)