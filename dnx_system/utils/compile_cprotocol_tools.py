#!/usr/bin/env python3

from __future__ import annotations

import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

# HOME_DIR = '/home/dnx/dnxfirewall'
HOME_DIR = '/home/free/Desktop/new_repos/dnxfirewall-cmd'

os.chdir(f'{HOME_DIR}/dnx_iptools/cprotocol_tools')

cmd = {'build_ext': build_ext}
ext = Extension(
    'cprotocol_tools', sources=['cprotocol_tools.pyx']
)

setup(
    name='cprotocol_tools', cmdclass=cmd, ext_modules=cythonize(ext, language_level='3')
)
