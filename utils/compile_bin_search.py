#!/usr/bin/env python3

import os

from setuptools import setup
from Cython.Build import cythonize

HOME_DIR = '/home/dnx/dnxfirewall'
os.chdir(HOME_DIR)

setup(
    ext_modules=cythonize('dnx_iptools/dnx_binary_search.pyx', language_level='3')
)
