
import unittest
import os

from pylioness.lioness import AES_SHA256_Lioness, Chacha20_Blake2b_Lioness

class Test_Lioness_basic(unittest.TestCase):

    def test_AES_SHA256_Lioness_end_to_end(self):
        plaintext = b"'What do we know,' he had said, 'of the world and the universe about us? Our means of receiving impressions are absurdly few, and our notions of surrounding objects infinitely narrow. We see things only as we are constructed to see them, and can gain no idea of their absolute nature. With five feeble senses we pretend to comprehend the boundlessly complex cosmos, yet other beings with wider, stronger, or different range of senses might not only see very differently the things we see, but might see and st"
        key = os.urandom(96)
        c = AES_SHA256_Lioness(key, len(plaintext))
        ciphertext = c.encrypt(plaintext)
        self.failUnlessEqual(len(plaintext), len(ciphertext))
        output = c.decrypt(ciphertext)
        self.failUnlessEqual(len(output), len(ciphertext))
        self.failUnlessEqual(output, plaintext)

    def test_Chacha20_Blake2_Lioness_end_to_end(self):
        plaintext = b"'What do we know,' he had said, 'of the world and the universe about us? Our means of receiving impressions are absurdly few, and our notions of surrounding objects infinitely narrow. We see things only as we are constructed to see them, and can gain no idea of their absolute nature. With five feeble senses we pretend to comprehend the boundlessly complex cosmos, yet other beings with wider, stronger, or different range of senses might not only see very differently the things we see, but might see and st"
        key = os.urandom(208)
        c = Chacha20_Blake2b_Lioness(key, len(plaintext))
        ciphertext = c.encrypt(plaintext)
        self.failUnlessEqual(len(plaintext), len(ciphertext))
        output = c.decrypt(ciphertext)
        self.failUnlessEqual(len(output), len(ciphertext))
        self.failUnlessEqual(output, plaintext)

    def test_vectors_Chacha20_Blake2_Lioness(self):
        vectors = [
            (
                b'\x00' * 208,
                b'v\xb8\xe0\xad\xa0\xf1=\x90@]j\xe5S\x86\xbd(\xbd\xd2\x19\xb8\xa0\x8d\xed\x1a\xa86\xef\xcc\x8bw\r\xc7\xdaAY|QWH\x8dw$\xe0?\xb8\xd8J7jC\xb8\xf4\x15\x18\xa1\x1c\xc3\x87\xb6i\xb2\xeee\x86\x9f\x07\xe7\xbeUQ8z\x98\xba\x97|s-\x08\r\xcb\x0f)\xa0H\xe3ei\x12\xc6S>2\xeez\xed)\xb7!v\x9c\xe6NC\xd5q3\xb0t\xd89\xd51\xed\x1f(Q\n\xfbE\xac\xe1\n\x1fKyMo',
                b'\x9b\xadB\xcf\x81\x92\xb4\tdx\xf7\x810\x1c\x92\n\x12\xfa*YVDG\x05\xc0\xce\xd5\x03\x9e\x89\xedRz\xfab\xc5\x08@g\xf2P\x84Z\xf6T\xfaV(\xc7ZX\xac\xe4\x1d\xcc\x17\x04q\x06\x11]7\xbb\xa2g\xd8\xa7\x93\xdef\x93\x95e\x84\x93/\n\xfbRq\xf9z\x89\xe4Oo\x90\xac\x1fH\xf0\xabe\xb3\xd0\xd9o\x18\xc7t$\xaf}\xa5$\xca\x82i*\xb6&\xde\x10x\x98 \xad\x14e\x10\x12\xa7\x85j\xe4\xd6(O'
            ),
            (
                b'\xff\xe3\xb2\xff-"\xbb\xd2\xa2\xb4/\x0e\xca.;\xfdF\xb9^`\xfcb.\xb5W\x1c\xc4\xed\xe5\x0c\x1c9\xff\xe2/\x1e\xa4\xe7\xa0\xb7E\xbb\x97\xd7\x9f\x02\x93\x9b\xaeK\xed\x83\xa1\xb0\xddDY\xd6\xa4m+:\xaeL\xa9\xce?\x82\x12B\x8e\xe5#q\x9d0\x06(\xb0\xf2\xe4\xae\x08\x85A\xf4\xac\x18\xac\xf6f\x1a\xc6B\x94\xa9\x84C\xcb\xbdU\x16\xfa\n\x11\n#-&\xf0u\xc7\xa4\xae\n\xb8@aJ\xe2\xaf\xf2\'S\xb1\xd2h\x18\xcf~\x12\x8eAOoq\x04X\x9b\x9dIA\xfa\xd4\xe4\xe2?\x8b\x19\x86>\xfb\xdfRY~\x93l\xf6\x97\x01"\x8dN\xdcl\x9e\x9eP#;&\xccb\xa2gIJ-r\xba\xdf\x1d\xf1\xfc\x11\xba\xd8\x9b\n\x93+\xd8\xf4[\x8e\xf2&\xca\xf0xI\xbfN\xaat\xea\xa3',
                b'v\xb8\xe0\xad\xa0\xf1=\x90@]j\xe5S\x86\xbd(\xbd\xd2\x19\xb8\xa0\x8d\xed\x1a\xa86\xef\xcc\x8bw\r\xc7\xdaAY|QWH\x8dw$\xe0?\xb8\xd8J7jC\xb8\xf4\x15\x18\xa1\x1c\xc3\x87\xb6i\xb2\xeee\x86\x9f\x07\xe7\xbeUQ8z\x98\xba\x97|s-\x08\r\xcb\x0f)\xa0H\xe3ei\x12\xc6S>2\xeez\xed)\xb7!v\x9c\xe6NC\xd5q3\xb0t\xd89\xd51\xed\x1f(Q\n\xfbE\xac\xe1\n\x1fKyMo',
                b'P\x88\xba4Q\xa9\\\xf1\x04\t\x80\x07\xf3\x00"hH\xab\xc7\xa0\xc0$\xe7\xbe\x06\x86n\xf6\xd6+\xf0\xa2\x85\xb8&\xcb\x97\xcf\x86(\t\x8a\xe7\xfa\t9\xee\x0f\x99\xadS\xca\xf9.\x0fX\xf4?\x9e\xd3\x1e~\xcf\x87\x18\xfa \xe3\x8c\xe0\xe5\xd6|\x1b\x851w\x1a\xca\x85j\xe5\xb9\xf1\x07Yw\xbd\xc7\xf03\xd1\x01\x9eNf\x92\xb8F\x03\x1dr~\xc6\xa1-$.\x7f\xdc\x13\xc5M3\xf6\x92\xfaM\x03\x85\x01\xa4\xd1!_O\x8c\xf0'
            ),
        ]

        for v in vectors:
            key = v[0]
            plaintext = v[1]
            want = v[2]
            c = Chacha20_Blake2b_Lioness(key, len(plaintext))
            ciphertext = c.encrypt(plaintext)
            self.failUnlessEqual(ciphertext, want)


if __name__ == '__main__':
    unittest.main()
