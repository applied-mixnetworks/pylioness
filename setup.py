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
    keywords=['python','cryptography'],
    install_requires=open('requirements.txt').readlines(),
    classifiers=[
        'Topic :: Security',
    ],
    #author=__author__,
    #author_email=__contact__,
    #url=__url__,
    #license=__license__,
    packages=["pylioness"],
    extras_require={
        "test": [
            "pytest",
            "pyflakes",
            "coverage",
            "tox",
        ]
    }
)
