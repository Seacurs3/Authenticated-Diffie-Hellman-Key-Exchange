# This file sets up the participant class, which represents a participant in this Diffie-Hellman key exchange demonstration. 

import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modular_math import modular_exponentiation


class Participant:
    def __init__(self, name, peer, allow_fixture=False):
        self.name = name          # fixed ASCII identity label, "Alice" or "Bob"
        self.peer = peer          # the identity this participant expects to talk to
        self.allow_fixture = allow_fixture  # explicit test-fixture path (permits p = 23)

        # Step 6: separate Ed25519 signing key pair, retained across exchanges.
        # The signing private key stays private; the public key is shared.
        self.signing_key = Ed25519PrivateKey.generate()
        self.verification_key = self.signing_key.public_key()

        # Filled in by trusted_setup(): peer name -> peer's authentic signing public key.
        self.trusted_keys = {}

        # Pending-session records, keyed by this participant's own nonce.
        self.sessions = {}
        # Completed sessions: nonce -> shared secret (kept locally, never sent).
        self.completed = {}


    # Step 5: Generate Diffie-Hellman keys
    def new_dh_keypair(self, p, g, private_key=None):
        while True:
            # Fresh private exponent for each exchange: 2 <= private <= p - 2
            #   private_key = secrets.randbelow(p - 3) + 2
            # (a fixed private_key is only passed in for the worked fixture)
            private = private_key if private_key is not None else secrets.randbelow(p - 3) + 2

            # Public value with our own square-and-multiply: A = g^a mod p
            public = modular_exponentiation(g, private, p)

            # If the new public value is outside 2 <= public <= p - 2,
            # generate another private exponent.
            if 2 <= public <= p - 2:
                return private, public
            if private_key is not None:
                raise ValueError("fixture private key gives an out-of-range public value")
