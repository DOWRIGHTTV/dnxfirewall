#!/usr/bin/env python3

import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

os.chdir('/home/dnx/dnxfirewall/dnx_iptools')

cmd = {'build_ext': build_ext}
ext = Extension(
    'dnx_binary_search', sources=['dnx_binary_search.pyx']
)

setup(
    name='DNX-BINARYSEARCH', cmdclass=cmd, ext_modules=cythonize(ext, language_level='3')
)
