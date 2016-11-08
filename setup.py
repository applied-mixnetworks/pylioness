# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

from setuptools import setup


description = '''
    python lioness block cipher
'''

setup(
    name='pylioness',
    version='0.0.1',
    description=description,
    keywords=['python', 'cryptography'],
    install_requires=open('requirements.txt').readlines(),
    classifiers=[
        'Topic :: Security',
    ],
    packages=["pylioness"],
)
