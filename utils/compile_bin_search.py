#!/usr/bin/env python3

import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

os.chdir('/home/dnx/dnxfirewall')

cmd = {'build_ext': build_ext}

setup(
    cmdclass=cmd, ext_modules=cythonize('dnx_iptools/dnx_binary_search.pyx', language_level='3')
)
