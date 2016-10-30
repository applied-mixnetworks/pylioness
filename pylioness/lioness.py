
from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.strxor import strxor
from Crypto.Util import number


class xcounter:
    # Implements a string counter to do AES-CTR mode
    i = 0
    def __init__(self, size):
        self.size = size

    def __call__(self):
        ii = number.long_to_bytes(self.i)
        ii = '\x00' * (self.size-len(ii)) + ii
        self.i += 1
        return ii

class Cipher:

    def __init__(self, key, block_size, secret_key_len, hash_key_len):
        self.key = key
        self.block_size = block_size
        self.secret_key_len = secret_key_len
        self.hash_key_len = hash_key_len
        self.min_block_size = secret_key_len
        self.k1 = key[:secret_key_len]
        self.k2 = key[secret_key_len:hash_key_len]
        self.k3 = key[secret_key_len+hash_key_len:secret_key_len*2+hash_key_len]
        self.k4 = key[(2*secret_key_len+hash_key_len):hash_key_len+(2*secret_key_len+hash_key_len)]

    def HMAC(self, key, data):
        m = HMAC.new(key, msg=data, digestmod=SHA256)
        return m.digest()

    def xor(self, str1, str2):
        # XOR two strings
        assert len(str1) == len(str2)
        return strxor(str1, str2)

    def encrypt(self, block):
        assert len(block) >= self.min_block_size

        l_size = self.secret_key_len
        r_size = self.block_size - l_size

	# Round 1: R = R ^ S(L ^ K1)
        tmp = self.xor(block[:l_size], self.k1)
        c = AES.new(tmp, AES.MODE_CTR, counter=xcounter(self.secret_key_len))
        r = c.encrypt(block[l_size:l_size+r_size])

	# Round 2: L = L ^ H(K2, R)
        l = self.xor(block[:l_size], self.HMAC(self.k2, r)[:l_size])

	# Round 3: R = R ^ S(L ^ K3)
        tmp = self.xor(l, self.k3)
        c = AES.new(tmp, AES.MODE_CTR, counter=xcounter(self.secret_key_len))
        r = c.encrypt(r)

        # Round 4: L = L ^ H(K4, R)
        l = self.xor(l, self.HMAC(self.k4, r)[:l_size])
	return l + r

    def decrypt(self, block):
        assert len(block) >= self.min_block_size

        l_size = self.secret_key_len
        r_size = self.block_size - l_size

        # Round 4: L = L ^ H(K4, R)
        l = self.xor(block[:l_size], self.HMAC(self.k4, block[l_size:l_size+r_size])[:l_size])

	# Round 3: R = R ^ S(L ^ K3)
        tmp = self.xor(l, self.k3)
        c = AES.new(tmp, AES.MODE_CTR, counter=xcounter(self.secret_key_len))
        r = c.encrypt(block[l_size:l_size+r_size])

	# Round 2: L = L ^ H(K2, R)
        l = self.xor(l, self.HMAC(self.k2, r)[:l_size])

	# Round 1: R = R ^ S(L ^ K1)
        tmp = self.xor(l, self.k1)
        c = AES.new(tmp, AES.MODE_CTR, counter=xcounter(self.secret_key_len))
        r = c.encrypt(r)

	return l + r
