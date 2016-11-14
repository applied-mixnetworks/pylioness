
import unittest
import os
import time

from pylioness.lioness import AES_SHA256_Lioness, Chacha20_Blake2b_Lioness


class Test_Lioness_benchmarks(unittest.TestCase):

    def test_timing_Chacha20_Blake2_Lioness(self):
        key = b'\xff\xe3\xb2\xff-"\xbb\xd2\xa2\xb4/\x0e\xca.;\xfdF\xb9^`\xfcb.\xb5W\x1c\xc4\xed\xe5\x0c\x1c9\xff\xe2/\x1e\xa4\xe7\xa0\xb7E\xbb\x97\xd7\x9f\x02\x93\x9b\xaeK\xed\x83\xa1\xb0\xddDY\xd6\xa4m+:\xaeL\xa9\xce?\x82\x12B\x8e\xe5#q\x9d0\x06(\xb0\xf2\xe4\xae\x08\x85A\xf4\xac\x18\xac\xf6f\x1a\xc6B\x94\xa9\x84C\xcb\xbdU\x16\xfa\n\x11\n#-&\xf0u\xc7\xa4\xae\n\xb8@aJ\xe2\xaf\xf2\'S\xb1\xd2h\x18\xcf~\x12\x8eAOoq\x04X\x9b\x9dIA\xfa\xd4\xe4\xe2?\x8b\x19\x86>\xfb\xdfRY~\x93l\xf6\x97\x01"\x8dN\xdcl\x9e\x9eP#;&\xccb\xa2gIJ-r\xba\xdf\x1d\xf1\xfc\x11\xba\xd8\x9b\n\x93+\xd8\xf4[\x8e\xf2&\xca\xf0xI\xbfN\xaat\xea\xa3'
        block = b"'What do we know,' he had said, 'of the world and the universe about us? Our means of receiving impressions are absurdly few, and our notions of surrounding objects infinitely narrow. We see things only as we are constructed to see them, and can gain no idea of their absolute nature. With five feeble senses we pretend to comprehend the boundlessly complex cosmos, yet other beings with wider, stronger, or different range of senses might not only see very differently the things we see, but might see and st"
        t0 = time.time()
        for _ in range(100):
            c = Chacha20_Blake2b_Lioness(key, len(block))
            ciphertext = c.encrypt(block)
        t1 = time.time()
        print("Time per chacha20+blake2 lioness block encrypt: %.2fms" % ((t1-t0)*1000.0/100))

    def test_timing_AES_SHA256_Lioness(self):
        block = b"'What do we know,' he had said, 'of the world and the universe about us? Our means of receiving impressions are absurdly few, and our notions of surrounding objects infinitely narrow. We see things only as we are constructed to see them, and can gain no idea of their absolute nature. With five feeble senses we pretend to comprehend the boundlessly complex cosmos, yet other beings with wider, stronger, or different range of senses might not only see very differently the things we see, but might see and st"
        key = os.urandom(96)
        t0 = time.time()
        for _ in range(100):        
            c = AES_SHA256_Lioness(key, len(block))
            ciphertext = c.encrypt(block)
        t1 = time.time()
        print("Time per aes_ctr+sha256 lioness block encrypt: %.2fms" % ((t1-t0)*1000.0/100))
