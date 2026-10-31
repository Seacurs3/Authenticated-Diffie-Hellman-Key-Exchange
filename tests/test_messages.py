"""Message validation and authentication tests (every attack in the Step 10 table)."""

import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authentication import ProtocolError, encode, trusted_setup
from eve import corrupt_signature, sign_with_eve_key, tamper
from participant import Participant
from protocol import alice_handle_response, alice_start, bob_handle_finish, bob_handle_init


def fixture_pair():
    alice = Participant("Alice", "Bob", allow_fixture=True)
    bob = Participant("Bob", "Alice", allow_fixture=True)
    trusted_setup(alice, bob)
    return alice, bob


class TestAttacks(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = fixture_pair()
        self.init = alice_start(self.alice, 23, 5, private_key=6)

    def response(self):
        return bob_handle_init(self.bob, self.init, private_key=15)

    def test_valid_messages(self):
        finish = alice_handle_response(self.alice, self.response())
        bob_handle_finish(self.bob, finish)

    def test_modify_A_without_resigning(self):
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, tamper(self.init, ["payload", "A"], 10))

    def test_modify_B_without_resigning(self):
        forged = tamper(self.response(), ["payload", "transcript", "B"], 17)
        with self.assertRaises(ProtocolError):
            alice_handle_response(self.alice, forged)
        self.assertEqual(self.alice.sessions, {})  # session aborted and cleared

    def test_modify_p_or_g(self):
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, tamper(self.init, ["payload", "p"], 47))
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, tamper(self.init, ["payload", "g"], 7))

    def test_modify_identity_labels(self):
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, tamper(self.init, ["payload", "initiator"], "Eve"))
        forged = tamper(self.response(), ["payload", "transcript", "responder"], "Eve")
        with self.assertRaises(ProtocolError):
            alice_handle_response(self.alice, forged)

    def test_corrupt_signature(self):
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, corrupt_signature(self.init))

    def test_sign_as_alice_with_eve_key(self):
        eve_key = Ed25519PrivateKey.generate()
        forged = sign_with_eve_key(self.init, eve_key, ["payload", "A"], 10)
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, forged)

    def test_wrong_trusted_key(self):
        self.bob.trusted_keys = {"Alice": Ed25519PrivateKey.generate().public_key()}
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, self.init)


class TestMalformedMessages(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = fixture_pair()
        self.init = alice_start(self.alice, 23, 5, private_key=6)

    def test_oversized(self):
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, b" " * 5000)

    def test_not_json(self):
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, b"8523")

    def test_duplicate_keys(self):
        raw = self.init.decode()
        dup = raw.replace('"signature":', '"signature":"00","signature":', 1).encode()
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, dup)

    def test_unexpected_field(self):
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, tamper(self.init, ["payload", "extra"], 1))

    def test_string_instead_of_integer(self):
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, tamper(self.init, ["payload", "A"], "8"))

    def test_malformed_nonce(self):
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, tamper(self.init, ["payload", "nonce_A"], "zz" * 32))

    def test_wrong_protocol_label(self):
        with self.assertRaises(ProtocolError):
            bob_handle_init(self.bob, tamper(self.init, ["payload", "protocol"], "v0"))

    def test_deterministic_encoding(self):
        self.assertEqual(encode({"p": 23, "g": 5, "A": 8}), b'{"A":8,"g":5,"p":23}')
        self.assertEqual(json.loads(self.init)["payload"]["p"], 23)


if __name__ == "__main__":
    unittest.main()
