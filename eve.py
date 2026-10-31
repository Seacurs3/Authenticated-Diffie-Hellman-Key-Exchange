"""Step 10: Eve's interception, tampering, and replay.

Eve controls simulated network messages but cannot modify the trusted
configuration or access Alice's or Bob's private keys.
"""

import json

from authentication import encode
from modular_math import modular_exponentiation


# ---------------------------------------------------------------------------
# First demonstrate the attack against the unauthenticated version
# ---------------------------------------------------------------------------
def unauthenticated_attack(p=23, g=5, a=6, b=15, e1=3, e2=7):
    # Alice and Bob compute their public values: A = g^a mod p, B = g^b mod p
    A = modular_exponentiation(g, a, p)
    B = modular_exponentiation(g, b, p)

    # Eve creates two private exponents:
    #   e1 = 3, E1 = 5^3 mod 23 = 10
    #   e2 = 7, E2 = 5^7 mod 23 = 17
    E1 = modular_exponentiation(g, e1, p)
    E2 = modular_exponentiation(g, e2, p)

    # Eve sends E1 to Alice as though from Bob, and E2 to Bob as though from Alice.
    alice_secret = modular_exponentiation(E1, a, p)   # Alice computes 10^6 mod 23 = 6
    eve_with_alice = modular_exponentiation(A, e1, p)  # Eve computes 8^3 mod 23 = 6
    bob_secret = modular_exponentiation(E2, b, p)     # Bob computes 17^15 mod 23 = 15
    eve_with_bob = modular_exponentiation(B, e2, p)   # Eve computes 19^7 mod 23 = 15

    # Alice and Bob now hold different secrets, and Eve knows both.
    return {
        "A": A, "B": B, "E1": E1, "E2": E2,
        "alice_secret": alice_secret, "eve_with_alice": eve_with_alice,
        "bob_secret": bob_secret, "eve_with_bob": eve_with_bob,
    }


# ---------------------------------------------------------------------------
# Tampering helpers for the authenticated version
# ---------------------------------------------------------------------------
def tamper(message, path, value):
    """Modify one field (e.g. ["payload", "transcript", "B"]) while keeping
    the original signature."""
    envelope = json.loads(message)
    target = envelope
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return encode(envelope)


def corrupt_signature(message):
    """Flip one hex digit of the signature."""
    envelope = json.loads(message)
    sig = envelope["signature"]
    envelope["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    return encode(envelope)


def sign_with_eve_key(message, eve_signing_key, path=None, value=None):
    """Optionally modify a field, then sign as "Alice"/"Bob" using Eve's own key."""
    envelope = json.loads(message)
    if path is not None:
        target = envelope
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    envelope["signature"] = eve_signing_key.sign(encode(envelope["payload"])).hex()
    return encode(envelope)
