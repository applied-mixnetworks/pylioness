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
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    license="GPLv3",
    packages=["pylioness"],
)
