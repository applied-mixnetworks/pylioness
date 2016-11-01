
"""
pylioness is a LIONESS block cipher implementation
"""

from __future__ import absolute_import
from __future__ import with_statement

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.strxor import strxor
from Crypto.Util import number
from pyblake2 import blake2b
from Cryptodome.Cipher import ChaCha20


class Chacha20Blake2bLioness(object):
    """
    I am a Lioness cipher implementation using the Chacha20 stream cipher
    and the Blake2b hash function.
    """

    def __init__(self, key, block_size):
        assert len(key) == 208
        self.key = key
        self.block_size = block_size
        self.secret_key_len = 40
        self.hash_key_len = 64
        self.key_len = 32
        self.nonce_len = 8
        self.cipher = Lioness(key, block_size, self.secret_key_len, self.hash_key_len,
                              self.stream_cipher_xor, self.hash_mac)

    def hash_mac(self, key, data):
        """
        I am a keyed-hash message authentication code
        using Blake2b.
        """
        return blake2b(data=data, key=key, digest_size=40).digest()

    def stream_cipher_xor(self, key, data):
        """
        I am a stream cipher wrapper function using Chacha20.
        """
        return ChaCha20.new(key=key[self.nonce_len:self.nonce_len+self.key_len],
                            nonce=key[:self.nonce_len]).encrypt(data)

    def encrypt(self, block):
        """
        I am essentially a proxy function to the cipher's
        encrypt method.
        """
        return self.cipher.encrypt(block)

    def decrypt(self, block):
        """
        I am essentially a proxy function to the cipher's
        decrypt method.
        """
        return self.cipher.decrypt(block)


class AESSHA256Lioness(object):
    """
    I am a Lioness cipher implementation using AES counter-mode for a stream cipher
    and the SHA256 hash function.
    """

    def __init__(self, key, block_size):
        assert len(key) == 96
        self.key = key
        self.block_size = block_size
        self.secret_key_len = 16
        self.hash_key_len = 32
        self.cipher = Lioness(key, block_size, self.secret_key_len,
                              self.hash_key_len, self.stream_cipher_xor, self.hash_mac)

    def hash_mac(self, key, data):
        """
        I am a keyed-hash message authentication code
        using SHA256.
        """
        return HMAC.new(key, msg=data, digestmod=SHA256).digest()

    def stream_cipher_xor(self, key, data):
        """
        I am a stream cipher wrapper function using AES in counter-mode.
        """
        class Xcounter(object):
            """
            I am a counter function used in the AES counter-mode
            stream cipher construction.
            """
            def __init__(self, size):
                self.i = 0
                self.size = size
            def __call__(self):
                if self.i > 2**self.size:
                    raise Exception("AES_stream_cipher counter exhausted.")
                ret = number.long_to_bytes(self.i)
                ret = '\x00' * (self.size-len(ret)) + ret
                self.i += 1
                return ret
        return AES.new(key, AES.MODE_CTR, counter=Xcounter(self.secret_key_len)).encrypt(data)

    def encrypt(self, block):
        """
        I am essentially a proxy function to the cipher's
        encrypt method.
        """
        return self.cipher.encrypt(block)

    def decrypt(self, block):
        """
        I am essentially a proxy function to the cipher's
        decrypt method.
        """
        return self.cipher.decrypt(block)


class Lioness(object):
    """
    I am a parameterized LIONESS block cipher implementation
    that allows you to choose which crypto primitives are used.
    """
    def __init__(self, key, block_size, secret_key_len, hash_key_len, stream_cipher_xor, hmac):
        self.key = key
        self.block_size = block_size
        self.secret_key_len = secret_key_len
        self.hash_key_len = hash_key_len
        self.min_block_size = secret_key_len
        self.stream_cipher_xor = stream_cipher_xor
        self.hash_mac = hmac
        self.key1 = key[:secret_key_len]
        self.key2 = key[secret_key_len:secret_key_len+hash_key_len]
        self.key3 = key[secret_key_len+hash_key_len:secret_key_len*2+hash_key_len]
        self.key4 = key[(2*secret_key_len+hash_key_len):hash_key_len+(2*secret_key_len+hash_key_len)]

    def xor(self, str1, str2):
        # XOR two strings
        assert len(str1) == len(str2)
        return strxor(str1, str2)

    def encrypt(self, block):
        """
        Encrypt a block using the Lioness block cipher.
        """
        assert len(block) >= self.min_block_size

        l_size = self.secret_key_len
        r_size = self.block_size - l_size

	# Round 1: R = R ^ S(L ^ K1)
        tmp = self.xor(block[:l_size], self.key1)
        r = self.stream_cipher_xor(tmp, block[l_size:l_size+r_size])

	# Round 2: L = L ^ H(K2, R)
        l = self.xor(block[:l_size], self.hash_mac(self.key2[:self.hash_key_len], r)[:l_size])

	# Round 3: R = R ^ S(L ^ K3)
        tmp = self.xor(l[:l_size], self.key3[:l_size])
        r = self.stream_cipher_xor(tmp, r)

        # Round 4: L = L ^ H(K4, R)
        l = self.xor(l, self.hash_mac(self.key4, r)[:l_size])

        return l + r

    def decrypt(self, block):
        """
        Decrypt a block using the Lioness block cipher.
        """
        assert len(block) >= self.min_block_size

        l_size = self.secret_key_len
        r_size = self.block_size - l_size

        # Round 4: L = L ^ H(K4, R)
        l = self.xor(block[:l_size], self.hash_mac(self.key4, block[l_size:l_size+r_size])[:l_size])

	# Round 3: R = R ^ S(L ^ K3)
        tmp = self.xor(l, self.key3)
        r = self.stream_cipher_xor(tmp, block[l_size:l_size+r_size])

	# Round 2: L = L ^ H(K2, R)
        l = self.xor(l, self.hash_mac(self.key2, r)[:l_size])

	# Round 1: R = R ^ S(L ^ K1)
        tmp = self.xor(l, self.key1)
        r = self.stream_cipher_xor(tmp, r)

        return l + r
