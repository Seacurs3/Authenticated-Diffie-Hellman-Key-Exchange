"""Complete exchange tests: key agreement and session state."""

import unittest

from authentication import ProtocolError, trusted_setup
from parameters import find_generator, generate_prime, prime_factors
from participant import Participant
from protocol import (alice_handle_response, alice_start, bob_handle_finish,
                      bob_handle_init, run_exchange)


def pair(allow_fixture=False):
    alice = Participant("Alice", "Bob", allow_fixture)
    bob = Participant("Bob", "Alice", allow_fixture)
    trusted_setup(alice, bob)
    return alice, bob


class TestKeyAgreement(unittest.TestCase):
    def test_fixed_p23_example(self):
        alice, bob = pair(allow_fixture=True)
        s_a, s_b = run_exchange(alice, bob, 23, 5, a=6, b=15)
        self.assertEqual((s_a, s_b), (2, 2))

    def test_p23_rejected_without_fixture_path(self):
        alice, bob = pair()
        with self.assertRaises(ProtocolError):
            run_exchange(alice, bob, 23, 5)

    def test_several_generated_exchanges(self):
        for bits in (16, 24, 32):
            for _ in range(3):
                p = generate_prime(bits)
                g = find_generator(p, prime_factors(p - 1))
                alice, bob = pair()
                s_a, s_b = run_exchange(alice, bob, p, g)
                self.assertEqual(s_a, s_b)


class TestSessionState(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = pair()
        p = generate_prime(16)
        self.p, self.g = p, find_generator(p, prime_factors(p - 1))

    def full_run(self):
        init = alice_start(self.alice, self.p, self.g)
        response = bob_handle_init(self.bob, init)
        finish = alice_handle_response(self.alice, response)
        bob_handle_finish(self.bob, finish)
        return init, response, finish

    def test_fresh_nonces(self):
        init1, _, _ = self.full_run()
        init2, _, _ = self.full_run()
        self.assertNotEqual(init1, init2)
        self.assertEqual(len(self.alice.completed), 2)

    def test_replay_old_response_into_fresh_alice_session(self):
        _, old_response, _ = self.full_run()
        alice_start(self.alice, self.p, self.g)  # fresh session with new nonce_A
        with self.assertRaises(ProtocolError):
            alice_handle_response(self.alice, old_response)

    def test_replay_old_finish_into_fresh_bob_session(self):
        old_init, _, old_finish = self.full_run()
        # An old initiation can provoke a new response (Bob does not cache initiations) ...
        bob_handle_init(self.bob, old_init)
        # ... but it cannot complete: the old finish does not match Bob's new nonce_B.
        with self.assertRaises(ProtocolError):
            bob_handle_finish(self.bob, old_finish)
        self.assertEqual(len(self.bob.completed), 1)

    def test_duplicate_finish_after_completion(self):
        _, _, finish = self.full_run()
        with self.assertRaises(ProtocolError):
            bob_handle_finish(self.bob, finish)

    def test_wrong_message_order(self):
        init = alice_start(self.alice, self.p, self.g)
        with self.assertRaises(ProtocolError):
            alice_handle_response(self.alice, init)      # init sent where response expected
        init = alice_start(self.alice, self.p, self.g)
        response = bob_handle_init(self.bob, init)
        with self.assertRaises(ProtocolError):
            bob_handle_finish(self.bob, response)        # response sent where finish expected


if __name__ == "__main__":
    unittest.main()
