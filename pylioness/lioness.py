
from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.strxor import strxor
from Crypto.Util import number
from pyblake2 import blake2b
from Cryptodome.Cipher import ChaCha20


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


class Chacha20_Blake2b_Lioness:

    def __init__(self, key, block_size):
        self.key = key
        self.block_size = block_size
        self.secret_key_len = 40
        self.hash_key_len = 64
        self.key_len = 32
        self.nonce_len = 8
        self.cipher = Lioness(key, block_size, self.secret_key_len, self.hash_key_len, self.stream_cipher_xor, self.HMAC)

    def HMAC(self, key, data):
        b = blake2b(data=data, key=key)
        return b.digest()

    def stream_cipher_xor(self, key, data):
        c = ChaCha20.new(key=key[self.nonce_len:self.nonce_len+self.key_len], nonce=key[:self.nonce_len])
        return c.encrypt(data)

    def encrypt(self, block):
        return self.cipher.encrypt(block)

    def decrypt(self, block):
        return self.cipher.decrypt(block)


class AES_SHA256_Lioness:

    def __init__(self, key, block_size):
        self.key = key
        self.block_size = block_size
        self.secret_key_len = 16
        self.hash_key_len = 32
        self.cipher = Lioness(key, block_size, self.secret_key_len, self.hash_key_len, self.stream_cipher_xor, self.HMAC)

    def HMAC(self, key, data):
        m = HMAC.new(key, msg=data, digestmod=SHA256)
        return m.digest()

    def stream_cipher_xor(self, key, data):
        c = AES.new(key, AES.MODE_CTR, counter=xcounter(self.secret_key_len))
        return c.encrypt(data)        

    def encrypt(self, block):
        return self.cipher.encrypt(block)

    def decrypt(self, block):
        return self.cipher.decrypt(block)


class Lioness:

    def __init__(self, key, block_size, secret_key_len, hash_key_len, stream_cipher_xor, hmac):
        self.key = key
        self.block_size = block_size
        self.secret_key_len = secret_key_len
        self.hash_key_len = hash_key_len
        self.min_block_size = secret_key_len
        self.stream_cipher_xor = stream_cipher_xor
        self.HMAC = hmac
        self.k1 = key[:secret_key_len]
        self.k2 = key[secret_key_len:hash_key_len]
        self.k3 = key[secret_key_len+hash_key_len:secret_key_len*2+hash_key_len]
        self.k4 = key[(2*secret_key_len+hash_key_len):hash_key_len+(2*secret_key_len+hash_key_len)]

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
        r = self.stream_cipher_xor(tmp, block[l_size:l_size+r_size])

	# Round 2: L = L ^ H(K2, R)
        l = self.xor(block[:l_size], self.HMAC(self.k2, r)[:l_size])

	# Round 3: R = R ^ S(L ^ K3)
        tmp = self.xor(l, self.k3)
        r = self.stream_cipher_xor(tmp, r)

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
        r = self.stream_cipher_xor(tmp, block[l_size:l_size+r_size])

	# Round 2: L = L ^ H(K2, R)
        l = self.xor(l, self.HMAC(self.k2, r)[:l_size])

	# Round 1: R = R ^ S(L ^ K1)
        tmp = self.xor(l, self.k1)
        r = self.stream_cipher_xor(tmp, r)

	return l + r
