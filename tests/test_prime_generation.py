"""Prime-generator integration tests: test the wrapper and validation behavior,
not the library's internal primality algorithm."""

import unittest

from Crypto.Util.number import isPrime

from parameters import generate_prime, validate_received_modulus


class TestGeneratePrime(unittest.TestCase):
    def test_exact_bit_length_and_oddness(self):
        for bits in (16, 24, 32):
            p = generate_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertEqual(p % 2, 1)
            self.assertTrue(2 ** (bits - 1) <= p < 2 ** bits)

    def test_default_is_16(self):
        self.assertEqual(generate_prime().bit_length(), 16)

    def test_library_validates_returned_prime(self):
        self.assertTrue(isPrime(generate_prime(20)))

    def test_invalid_sizes(self):
        for bad in (12, 15, 33):
            with self.assertRaises(ValueError):
                generate_prime(bad)
        for bad in (True, False, 16.0, "16", None):
            with self.assertRaises(TypeError):
                generate_prime(bad)


class TestReceivedModulus(unittest.TestCase):
    def test_reject_composite(self):
        with self.assertRaises(ValueError):
            validate_received_modulus(32769)

    def test_wrong_types(self):
        for bad in ("65521", 65521.0, True):
            with self.assertRaises(TypeError):
                validate_received_modulus(bad)

    def test_out_of_range_sizes(self):
        with self.assertRaises(ValueError):
            validate_received_modulus(23)              # p = 23 only via fixture path
        with self.assertRaises(ValueError):
            validate_received_modulus(4294967311)      # 33-bit prime

    def test_accept(self):
        self.assertTrue(validate_received_modulus(65521))
        self.assertTrue(validate_received_modulus(23, allow_fixture=True))
        with self.assertRaises(ValueError):
            validate_received_modulus(21, allow_fixture=True)


if __name__ == "__main__":
    unittest.main()
