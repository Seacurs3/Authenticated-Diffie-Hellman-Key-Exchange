"""Step 1: Implement square-and-multiply.

modular_exponentiation(base, exponent, modulus) calculates
base^exponent mod modulus without constructing the full power.
"""


def modular_exponentiation(base, exponent, modulus):
    # validate integer inputs
    # (bool is a subclass of int in Python, so reject it explicitly)
    for value in (base, exponent, modulus):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("base, exponent, and modulus must be integers")

    # reject exponent < 0 or modulus <= 0
    if exponent < 0:
        raise ValueError("exponent must be nonnegative")
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    # 1. Set result = 1 % modulus.  (gives 0 when modulus is 1)
    result = 1 % modulus

    # 2. Set base = base % modulus.  (also turns a negative base into 0..modulus-1)
    base = base % modulus

    # 3. While exponent is greater than zero:
    while exponent > 0:
        # - If exponent is odd (lowest binary digit is 1), the current
        #   power contributes to the result: result = (result * base) % modulus
        if exponent % 2 == 1:
            result = (result * base) % modulus

        # - Square the base to get the next power of two: base = (base * base) % modulus
        base = (base * base) % modulus

        # - Halve the exponent to move to the next binary digit: exponent = exponent // 2
        exponent = exponent // 2

    # 4. Return result  (always in the range 0 through modulus - 1)
    return result
