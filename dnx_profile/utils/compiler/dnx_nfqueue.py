#!/usr/bin/env python3

import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

# COMPILER DIRECTIVES
DIRECTIVES = {
    'language_level': '3',
    'boundscheck': False,
    'cdivision': True
}

HOME_DIR = os.environ.get('HOME_DIR')
os.chdir(f'{HOME_DIR}/dnx_netmods/dnx_netfilter')

cmd = {'build_ext': build_ext}
ext = Extension(
    'dnx_nfqueue', sources=['dnx_nfqueue.pyx'],
    include_dirs=[f'{HOME_DIR}/libraries'],
    library_dirs=['usr/local/lib'],
    libraries=['netfilter_queue']
)

setup(
    name='dnx-nfqueue', cmdclass=cmd,
    ext_modules=cythonize(ext, compiler_directives=DIRECTIVES)
)
