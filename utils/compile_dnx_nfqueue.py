#!/usr/bin/env python3

import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

os.chdir('/home/dnx/dnxfirewall')

cmd = {'build_ext': build_ext}
ext = Extension(
    'dnx_nfqueue', sources=['dnx_netfilter/dnx_nfqueue.pyx'], libraries=['netfilter_queue']
)

setup(
    name='DNX-NFQUEUE', cmdclass=cmd, ext_modules=cythonize(ext, language_level='3')
)