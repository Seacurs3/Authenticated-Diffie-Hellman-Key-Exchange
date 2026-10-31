"""Fixed mathematical tests: exponentiation, factorization, generator, key agreement."""

import unittest

from modular_math import modular_exponentiation
from parameters import is_generator, prime_factors


class TestModularExponentiation(unittest.TestCase):
    def test_known_result(self):
        self.assertEqual(modular_exponentiation(5, 6, 23), 8)

    def test_exponent_zero(self):
        self.assertEqual(modular_exponentiation(5, 0, 23), 1)

    def test_modulus_one(self):
        self.assertEqual(modular_exponentiation(5, 0, 1), 0)

    def test_negative_base(self):
        self.assertEqual(modular_exponentiation(-5, 3, 23), pow(-5, 3, 23))

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            modular_exponentiation(5, -1, 23)
        with self.assertRaises(ValueError):
            modular_exponentiation(5, 6, 0)
        with self.assertRaises(TypeError):
            modular_exponentiation(5.0, 6, 23)
        with self.assertRaises(TypeError):
            modular_exponentiation(5, "6", 23)
        with self.assertRaises(TypeError):
            modular_exponentiation(True, 6, 23)

    def test_comparison_with_pow(self):
        # pow(base, exponent, modulus) is used only as an independent reference.
        for base, exp, mod in [(2, 100, 97), (123456, 65537, 4294967291), (7, 1, 13), (0, 5, 11)]:
            self.assertEqual(modular_exponentiation(base, exp, mod), pow(base, exp, mod))


class TestFactorization(unittest.TestCase):
    def test_one(self):
        self.assertEqual(prime_factors(1), set())

    def test_22(self):
        self.assertEqual(prime_factors(22), {2, 11})

    def test_repeated_factors(self):
        self.assertEqual(prime_factors(65536), {2})

    def test_invalid(self):
        with self.assertRaises(ValueError):
            prime_factors(0)
        with self.assertRaises(TypeError):
            prime_factors(True)


class TestGenerator(unittest.TestCase):
    def test_p23(self):
        factors = prime_factors(22)
        self.assertTrue(is_generator(5, 23, factors))
        self.assertFalse(is_generator(2, 23, factors))

    def test_p65537(self):
        self.assertTrue(is_generator(3, 65537, prime_factors(65536)))


class TestKeyAgreementFixture(unittest.TestCase):
    def test_p23_example(self):
        A = modular_exponentiation(5, 6, 23)
        B = modular_exponentiation(5, 15, 23)
        self.assertEqual((A, B), (8, 19))
        self.assertEqual(modular_exponentiation(B, 6, 23), 2)
        self.assertEqual(modular_exponentiation(A, 15, 23), 2)


if __name__ == "__main__":
    unittest.main()
