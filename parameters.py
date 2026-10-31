# Parameters sets up the primes and other parameters for the Diffie-Hellman key exchange
# Uses the crypto library to generate secure primes and validate them

import secrets

from Crypto.Util.number import getPrime, isPrime

from modular_math import modular_exponentiation

# Required prime sizes: exact bit lengths from 16 to 32 inclusive, 16 is the default.
MIN_BITS = 16
MAX_BITS = 32
DEFAULT_BITS = 16


def validate_bits(bits):
    # Reject Boolean values and nonintegers.
    if not isinstance(bits, int) or isinstance(bits, bool):
        raise TypeError("prime size must be an integer")
    # Reject sizes outside 16..32.
    if bits < MIN_BITS or bits > MAX_BITS:
        raise ValueError("prime size must be between 16 and 32 bits.")



# Step 2: Generate the public modulus using a library

def generate_prime(bits=DEFAULT_BITS):
    # 1. Validate that bits is an integer from 16 through 32 inclusive.
    # Reject Boolean values, nonintegers, and out-of-range values.
    validate_bits(bits)

    # 2. Call the library generator to obtain an exact bits-bit prime.
    # (PyCryptodome handles candidate selection and its internal primality checks.)
    p = getPrime(bits, randfunc=secrets.token_bytes)

    # 3. Confirm that p.bit_length() equals bits and p is odd.
    #    So 2^(bits - 1) <= p < 2^bits.
    if p.bit_length() != bits or p % 2 == 0:
        raise RuntimeError("library returned a prime of the wrong size")

    # 4. Return p.  (The total time of this wrapper is measured by the caller in main.py.)
    return p



# Validates the received modulus 
def validate_received_modulus(p, allow_fixture=False):
    # Check its type.
    if not isinstance(p, int) or isinstance(p, bool):
        raise TypeError("modulus must be an integer")

    # Check permitted bit length. p = 23 (or other small fixtures) is only
    # permitted through the explicit test-fixture path.
    if not allow_fixture and not (MIN_BITS <= p.bit_length() <= MAX_BITS):
        raise ValueError("modulus must be 16-32 bits")
    if allow_fixture and not (2 < p < 2 ** MAX_BITS):
        raise ValueError("fixture modulus out of range")

    # Call the library's isPrime(p). Reject if it returns False.
    if not isPrime(p):
        raise ValueError("modulus is not prime")

    return True



# Step 3: Factor p - 1
def prime_factors(n):
    # Return every distinct prime factor of n, without duplicates.
    # Accept positive integers.
    if not isinstance(n, int) or isinstance(n, bool):
        raise TypeError("n must be an integer")
    if n <= 0:
        raise ValueError("n must be positive")

    factors = set()  # For n = 1, this stays an empty set.

    # 1. Divide out all factors of 2, recording 2 once.
    if n % 2 == 0:
        factors.add(2)
        while n % 2 == 0:
            n //= 2

    # 2. Try odd divisors starting at 3.
    divisor = 3
    # 4. Stop when divisor * divisor exceeds the remaining n.
    while divisor * divisor <= n:
        # 3. For each divisor, divide out all occurrences and record it once.
        if n % divisor == 0:
            factors.add(divisor)
            while n % divisor == 0:
                n //= divisor
        divisor += 2

    # 5. If the remainder exceeds 1, record it.
    if n > 1:
        factors.add(n)

    return factors


# Step 4: Find and verify a generator
def is_generator(g, p, factors):
    #A primitive generator must have the full order p - 1.
    if not isinstance(g, int) or isinstance(g, bool):
        return False
    # Candidates are 2 through p - 2.
    if g < 2 or g > p - 2:
        return False

    # For each distinct prime factor r of p - 1, test:
    # modular_exponentiation(g, (p - 1) // r, p) != 1
    # Reject g if any result is 1. Accept it only if all checks pass.
    for r in factors:
        if modular_exponentiation(g, (p - 1) // r, p) == 1:
            return False
    return True

# Search candidates g in 2 through p - 2 using the complete set of distinct prime factors of p - 1
# raises ValueError if no generator is found
def find_generator(p, factors):
    for g in range(2, p - 1):
        if is_generator(g, p, factors):
            return g
    raise ValueError("no generator found")
