# Main function for the Diffie-Hellman key exchange demonstration.

import platform
import sys
import time

import Crypto
import cryptography

from authentication import ProtocolError, trusted_setup
from eve import tamper, unauthenticated_attack
from parameters import DEFAULT_BITS, find_generator, generate_prime, prime_factors, validate_bits
from participant import Participant
from protocol import alice_handle_response, alice_start, bob_handle_finish, bob_handle_init

# Creation of alice and bob for the DH key exchange. 
def make_participants(allow_fixture=False):
    alice = Participant("Alice", "Bob", allow_fixture)
    bob = Participant("Bob", "Alice", allow_fixture)
    trusted_setup(alice, bob)
    return alice, bob

# Performs the key exchange between the participants
# Returns the shared secret if theres a success
# Raises ProtocolError if theres a failure
def successful_exchange(bits):
    print("=== Authenticated exchange ===")
    print(f"Requested prime size: {bits} bits")
    p = generate_prime(bits)
    print("Modulus: generated using library prime generator")
    print(f"Modulus bit length: {p.bit_length()}")
    g = find_generator(p, prime_factors(p - 1))

    # Create the participants
    alice, bob = make_participants()
    init = alice_start(alice, p, g)
    response = bob_handle_init(bob, init)          # raises if p, g, A or signature fail
    print("Received modulus library validation: PASS")
    print("Generator: validated")
    print("Alice initiation signature: VALID")
    finish = alice_handle_response(alice, response)
    print("Bob response signature: VALID")
    nonce_B = bob_handle_finish(bob, finish)
    print("Alice finish signature: VALID")
    print("Transcript authenticated: YES")

    # The test coordinator inspects both local results; secrets are not sent.
    nonce_A = next(iter(alice.completed))
    match = alice.completed[nonce_A] == bob.completed[nonce_B]

    # Prints the results of the exchange and whether the shared secrets match. 
    print(f"Shared-secret equality in local test: {'PASS' if match else 'FAIL'}")
    print("Explicit key confirmation: NOT IMPLEMENTED")
    print()

# Demonstrates Eve's ability to perform a MITM attack against an unauthenticated DH exchange
def eve_demo():
    print("=== Eve vs. unauthenticated DH (fixture p=23, g=5, a=6, b=15) ===")
    r = unauthenticated_attack()
    print(f"Eve sends E1={r['E1']} to Alice as Bob, E2={r['E2']} to Bob as Alice")
    print(f"[classroom debug] Alice computes {r['alice_secret']}, Eve computes {r['eve_with_alice']}")
    print(f"[classroom debug] Bob computes {r['bob_secret']}, Eve computes {r['eve_with_bob']}")
    print("Alice and Bob hold different secrets, and Eve knows both.")
    print()

    print("=== Eve vs. authenticated DH (same fixture) ===")
    alice, bob = make_participants(allow_fixture=True)
    init = alice_start(alice, 23, 5, private_key=6)
    response = bob_handle_init(bob, init, private_key=15)
    # Eve replaces B with her own public value while keeping Bob's signature.
    forged = tamper(response, ["payload", "transcript", "B"], r["E1"])
    print("Eve modified Bob's public value.")
    try:
        alice_handle_response(alice, forged)
    except ProtocolError as exc:
        print(f"Bob response signature: INVALID ({exc})")
        print("Exchange aborted.")
    print()

# Measures the performance of the DH key exchange for different prime sizes and reports the results in a table
def performance(trials=3):
    print("=== Performance ===")
    print(f"Environment: Python {platform.python_version()} on {platform.platform()}; "
          f"cryptography {cryptography.__version__}; pycryptodome {Crypto.__version__}")
    print("| Bits | Trial | Prime generation (s) | Factorization (s) | Generator search (s) "
          "| Authenticated | Secrets match |")
    print("|---|---|---|---|---|---|---|")
    for bits in (16, 24, 32):
        for trial in range(1, trials + 1):
            # Measure the total time taken by the prime-generation wrapper.
            t0 = time.perf_counter()
            p = generate_prime(bits)
            t1 = time.perf_counter()
            factors = prime_factors(p - 1)
            t2 = time.perf_counter()
            g = find_generator(p, factors)
            t3 = time.perf_counter()

            alice, bob = make_participants()
            try:
                init = alice_start(alice, p, g)
                nonce_A = next(iter(alice.sessions))
                finish = alice_handle_response(alice, bob_handle_init(bob, init))
                nonce_B = bob_handle_finish(bob, finish)
                authenticated = "Yes"
                match = "Yes" if alice.completed[nonce_A] == bob.completed[nonce_B] else "No"
            except ProtocolError:
                authenticated, match = "No", "No"
            print(f"| {bits} | {trial} | {t1 - t0:.6f} | {t2 - t1:.6f} | {t3 - t2:.6f} "
                  f"| {authenticated} | {match} |")
    print()

# Parses the command line to determine the prime size in number of bits
def parse_bits(argv):
    if len(argv) < 2:
        return DEFAULT_BITS
    try:
        bits = int(argv[1])  # reject noninteger input
    except ValueError:
        raise ValueError("prime size must be an integer.")
    validate_bits(bits)
    return bits


if __name__ == "__main__":
    try:
        bits = parse_bits(sys.argv)
    except (TypeError, ValueError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    successful_exchange(bits)
    eve_demo()
    performance()
