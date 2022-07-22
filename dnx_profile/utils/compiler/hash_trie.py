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
os.chdir(f'{HOME_DIR}/dnx_iptools/hash_trie')

cmd = {'build_ext': build_ext}
ext = Extension(
    'hash_trie', sources=['hash_trie.pyx']
)

setup(
    name='dnx-hash-trie', cmdclass=cmd,
    ext_modules=cythonize(ext, compiler_directives=DIRECTIVES)
)
