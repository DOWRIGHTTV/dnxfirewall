#!/usr/bin/env python3

from __future__ import annotations

import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

HOME_DIR = os.environ.get('HOME_DIR')

os.chdir(f'{HOME_DIR}/dnx_netmods/dnx_netfilter')

cmd = {'build_ext': build_ext}
ext = Extension(
    'dnx_nfqueue', sources=['dnx_nfqueue.pyx'], libraries=['netfilter_queue']
)

setup(
    name='dnx-nfqueue', cmdclass=cmd, ext_modules=cythonize(ext, language_level='3')
)
