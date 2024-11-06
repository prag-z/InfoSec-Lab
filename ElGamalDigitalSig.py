from Crypto.Util.number import getPrime, inverse, bytes_to_long
from Crypto.Hash import SHA256
import random


def generate_keys(bits):
    """Generate ElGamal signature keys."""
    p = getPrime(bits)  # A large prime p
    g = random.randint(2, p - 2)  # Generator of the group
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key
    return p, g, x, h


def gcd(a, b):
    """Compute the GCD of a and b."""
    while b != 0:
        a, b = b, a % b
    return a


def sign_message(p, g, x, message):
    """Sign the message using ElGamal signature scheme."""
    max_attempts = 1000  # Maximum attempts to find a valid k
    attempts = 0

    while attempts < max_attempts:
        k = random.randint(1, p - 2)
        # Ensure that k is coprime to p-1
        if gcd(k, p - 1) == 1:
            break
        attempts += 1

    if attempts == max_attempts:
        raise ValueError("Unable to find a valid k after multiple attempts.")

    r = pow(g, k, p)
    k_inv = inverse(k, p - 1)  # Modular inverse of k
    H = bytes_to_long(SHA256.new(message).digest())

    s = (k_inv * (H + x * r)) % (p - 1)

    # Check if s is valid
    if s == 0 or gcd(s, p - 1) != 1:
        raise ValueError("Invalid signature generated: s is not valid.")

    return r, s


def verify_signature(p, g, h, message, signature):
    """Verify the ElGamal signature."""
    r, s = signature
    H = bytes_to_long(SHA256.new(message).digest())

    # Ensure s is valid before computing its inverse
    if s == 0 or gcd(s, p - 1) != 1:
        return False

    w = inverse(s, p - 1)  # Modular inverse of s
    u1 = (H * w) % (p - 1)
    u2 = (r * w) % (p - 1)

    v = (pow(g, u1, p) * pow(h, u2, p)) % p

    return v == r


# Example usage
if __name__ == "__main__":
    bits = 512  # Key size in bits
    p, g, x, h = generate_keys(bits)

    message = b"This is a confidential message."
    signature = sign_message(p, g, x, message)

    print(f"Signature: r = {signature[0]}, s = {signature[1]}")

    is_valid = verify_signature(p, g, h, message, signature)
    print(f"Signature valid: {is_valid}")
