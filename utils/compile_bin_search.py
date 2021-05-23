#!/usr/bin/env python3

from setuptools import setup
from Cython.Build import cythonize

HOME_DIR = '/home/dnx/dnxfirewall'

setup(
    ext_modules=cythonize(f'{HOME_DIR}/dnx_iptools/dnx_binary_search.pyx', language_level='3')
)