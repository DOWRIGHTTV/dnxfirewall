#!/usr/bin/env python3

import os
import shutil
import glob

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
os.chdir(f'{HOME_DIR}/dnx_secmods/cfirewall')

SOURCES = [
    f'{HOME_DIR}/dnx_ctools/inet_tools.c',
    'src/dnx_nfq.c', 'src/firewall.c', 'src/nat.c', 'src/match.c', 'fw_main/fw_main.pyx'
]

cmd = {'build_ext': build_ext}
ext = Extension(
    'fw_main', sources=SOURCES,
    include_dirs=[f'{HOME_DIR}/dnx_system/libraries', f'{HOME_DIR}/dnx_ctools/include', 'include'],
    library_dirs=['usr/local/lib'],
    libraries=['netfilter_queue']
)

INCLUDE_PATHS = [f'{os.getcwd()}/fw_main']

setup(
    name='cfirewall', cmdclass=cmd,
    ext_modules=cythonize(ext, language_level='3', include_path=INCLUDE_PATHS, compiler_directives=DIRECTIVES)
)

try:
    shutil.move(glob.glob('fw_main.*.so')[0], 'fw_main/fw_main.so')
except:
    pass