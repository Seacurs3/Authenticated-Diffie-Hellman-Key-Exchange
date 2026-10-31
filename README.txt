Authenticated Diffie-Hellman Key Exchange Project.

This project is a local Python simulation of an authenticated Diffie-Hellman key exchange
between Alice and Bob. It uses library prime generation (PyCryptodome),
Ed25519 signatures (cryptography), and an implementation of the square-and-multiply function. 
This project also demonstrates a successful exchange and the detection of an 
attacker (Eve) who is modifying the exchange.

Included is also a .docx report which explains the functions, code, tests the code, and a 
comparison to ECDH

REQUIREMENTS

- Python 3
- cryptography 50.0.1
- pycryptodome 4.2.0

Standard libraries used: secrets, json, time, hashlib, unittest


SETUP: 

From the project folder:

    python -m pip install -r requirements.txt


RUN THE PROJECT: 

    python main.py          (default runtime sets prime size: 16 bits)
    python main.py 24       (any integer from 16 through 32)

RESULTS:
  1. A successful authenticated exchange
  2. Eve's attack on the unauthenticated version, then its rejection in
     the authenticated version
  3. A timing table: three exchanges each at 16, 24, and 32 bits

Sizes outside 16-32, or noninteger input, print an error and exit:

    python main.py 12
    Error: prime size must be between 16 and 32 bits.


TEST

From the project folder:

  python -m unittest discover tests

  tests/test_math.py              Fixed mathematical tests: exponentiation,
                                  factorization, generator, p = 23 key agreement
  tests/test_prime_generation.py  Prime-generator integration tests and
                                  received-modulus validation
  tests/test_messages.py          Message validation and every required attack
  tests/test_exchange.py          Complete exchanges and session state
                                  (replays, duplicates, message order)


Files and their responsibilities:

  modular_math.py     Square-and-multiply
  parameters.py       Library prime-generation wrapper, received-modulus validation, factorization, generator selection
  participant.py      Local DH and signing state
  authentication.py   Trusted-key lookup, encoding, signatures
  protocol.py         Message processing and session state
  eve.py              Interception, tampering, and replay
  main.py             Run demonstrations and timing
  tests/              Automated tests


NOTE: 

This is an educational simulation, not a production protocol. The 16-32-bit
primes are small enough to brute-force, the exponentiation is not
constant-time, and no explicit key confirmation is implemented.
