from setuptools import setup
from Cython.Build import cythonize

py_files=['ocimonitor_root.py']

setup(
    ext_modules=cythonize(py_files),
)