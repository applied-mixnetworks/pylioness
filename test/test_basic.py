
import unittest
import os

from pylioness.lioness import AES_SHA256_Lioness, Chacha20_Blake2b_Lioness

class Test_Lioness_basic(unittest.TestCase):

    def test_AES_SHA256_Lioness_end_to_end(self):
        plaintext = "'What do we know,' he had said, 'of the world and the universe about us? Our means of receiving impressions are absurdly few, and our notions of surrounding objects infinitely narrow. We see things only as we are constructed to see them, and can gain no idea of their absolute nature. With five feeble senses we pretend to comprehend the boundlessly complex cosmos, yet other beings with wider, stronger, or different range of senses might not only see very differently the things we see, but might see and st"
        key = os.urandom(208)
        c = AES_SHA256_Lioness(key, len(plaintext))
        ciphertext = c.encrypt(plaintext)
        self.failUnlessEqual(len(plaintext), len(ciphertext))
        output = c.decrypt(ciphertext)
        self.failUnlessEqual(len(output), len(ciphertext))
        self.failUnlessEqual(output, plaintext)

    def test_Chacha20_Blake2_Lioness_end_to_end(self):
        plaintext = "'What do we know,' he had said, 'of the world and the universe about us? Our means of receiving impressions are absurdly few, and our notions of surrounding objects infinitely narrow. We see things only as we are constructed to see them, and can gain no idea of their absolute nature. With five feeble senses we pretend to comprehend the boundlessly complex cosmos, yet other beings with wider, stronger, or different range of senses might not only see very differently the things we see, but might see and st"
        key = os.urandom(208)
        c = Chacha20_Blake2b_Lioness(key, len(plaintext))
        ciphertext = c.encrypt(plaintext)
        self.failUnlessEqual(len(plaintext), len(ciphertext))
        output = c.decrypt(ciphertext)
        self.failUnlessEqual(len(output), len(ciphertext))
        self.failUnlessEqual(output, plaintext)


if __name__ == '__main__':
    unittest.main()
