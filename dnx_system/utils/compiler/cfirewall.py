#!/usr/bin/env python3

import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext
from Cython.Compiler import Options

# COMPILER OPTIONS
Options.annotate = False # FLIP TRUE FOR HTML VIEWABLE OUTPUT

Options.docstrings = False
Options.emit_code_comments = False

# COMPILER DIRECTIVES
DIRECTIVES = {
    'boundscheck': False,
    'cdivision': True
}

HOME_DIR = os.environ.get('HOME_DIR')
os.chdir(f'{HOME_DIR}/dnx_secmods/cfirewall/fw_main')

cmd = {'build_ext': build_ext}
ext = Extension(
    'fw_main', sources=['fw_main.pyx'],
    include_dirs=[f'{HOME_DIR}/libraries'],
    library_dirs=['usr/local/lib'],
    libraries=['netfilter_queue']
)

INCLUDE_PATHS = [os.getcwd(), f'{HOME_DIR}/dnx_secmods/cfirewall', f'{HOME_DIR}/dnx_iptools']

setup(
    name='cfirewall', cmdclass=cmd,
    ext_modules=cythonize(ext, language_level='3', include_path=INCLUDE_PATHS, compiler_directives=DIRECTIVES)
)
