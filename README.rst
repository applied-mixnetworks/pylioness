README
======

.. image:: https://travis-ci.org/david415/pylioness.png?branch=master
    :target: https://www.travis-ci.org/david415/pylioness
    :alt: travis

.. image:: https://coveralls.io/repos/github/david415/pylioness/badge.svg?branch=master
    :target: https://coveralls.io/github/david415/pylioness
    :alt: coveralls



Warning
=======
This code has not been formally audited by a cryptographer. It therefore should not
be considered safe or correct. Use it at your own risk! (however test vectors are verified using
other language implementations: rust, golang, python trinity!)


overview
--------

pylioness is a parameterized implementation of the LIONESS wide block cipher.
Use it with AES in counter mode + Sha256 or Chacha20 + Blake2b.

