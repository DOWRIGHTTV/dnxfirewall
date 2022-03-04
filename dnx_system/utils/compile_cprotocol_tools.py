#!/usr/bin/env python3

from __future__ import annotations

import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

os.chdir('/home/dnx/dnxfirewall/dnx_gentools')

cmd = {'build_ext': build_ext}
ext = Extension(
    'cprotocol_tools', sources=['cprotocol_tools.pyx']
)

setup(
    name='cprotocol_tools', cmdclass=cmd, ext_modules=cythonize(ext, language_level='3')
)
