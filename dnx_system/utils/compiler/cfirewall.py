#!/usr/bin/env python3

from __future__ import annotations

import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

HOME_DIR = os.environ.get('HOME_DIR')

os.chdir(f'{HOME_DIR}/dnx_secmods/cfirewall/fw_main')

cmd = {'build_ext': build_ext}
ext = Extension(
    'fw_main', sources=['fw_main.pyx'], libraries=['netfilter_queue']
)

cyonize = cythonize(ext, language_level='3', include_path=[os.getcwd(), f'{HOME_DIR}/dnx_iptools'])

setup(name='cfirewall', cmdclass=cmd, ext_modules=cyonize)
