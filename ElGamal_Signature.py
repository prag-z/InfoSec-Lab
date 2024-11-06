import random
from sympy import mod_inverse, isprime
from hashlib import sha256

def generate_prime_candidate(length):
    """Generate a prime number of specified bit length."""
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1  # Ensure p is odd and has the correct bit length
    return p

def generate_prime(length):
    """Generate a random prime number of specified bit length."""
    p = generate_prime_candidate(length)
    while not isprime(p):
        p = generate_prime_candidate(length)
    return p

def gcd(a, b):
    """Calculate the greatest common divisor."""
    while b:
        a, b = b, a % b
    return a

def generate_keys(bit_length=512):
    """Generate ElGamal keys."""
    p = generate_prime(bit_length)
    g = 2  # Primitive root modulo p
    x = random.randint(1, p - 2)  # Private key
    y = pow(g, x, p)  # Public key: y = g^x mod p
    return (p, g, x, y)

def hash_message(message):
    """Hash the message using SHA-256."""
    message_hash = sha256(message.encode()).hexdigest()
    return int(message_hash, 16)

def sign_message(p, g, x, message):
    """Generate a signature for the given message."""
    H_m = hash_message(message) % (p - 1)
    
    while True:
        k = random.randint(1, p - 2)
        while gcd(k, p - 1) != 1:  # Ensure k is coprime with p-1
            k = random.randint(1, p - 2)
        
        r = pow(g, k, p)  # r = g^k mod p
        k_inverse = mod_inverse(k, p - 1)
        s = (k_inverse * (H_m + x * r)) % (p - 1)  # s = k^(-1) * (H(m) + xr) mod (p-1)

        # Ensure that s is coprime to p-1 to avoid issues with modular inverse later
        if gcd(s, p - 1) == 1:
            break  # Valid signature found, exit the loop

    return (r, s)

def verify_signature(p, g, y, message, signature):
    """Verify the given signature for the message."""
    r, s = signature
    if not (0 < r < p and 0 < s < p - 1):
        print("Signature components are out of valid range.")
        return False
    
    H_m = hash_message(message) % (p - 1)
    
    try:
        w = mod_inverse(s, p - 1)  # Modular inverse of s mod (p-1)
    except ValueError:
        print("Modular inverse of s does not exist.")
        return False
    
    u1 = (H_m * w) % (p - 1)
    u2 = (r * w) % (p - 1)

    v1 = pow(g, u1, p)
    v2 = (pow(y, u2, p) * r) % p

    print(f"u1: {u1}, u2: {u2}")
    print(f"v1: {v1}, v2: {v2}")
    
    return v1 == v2

# Example usage
if __name__ == "__main__":
    # Key generation
    p, g, x, y = generate_keys()
    print("Public key (p, g, y):", (p, g, y))
    print("Private key x:", x)

    # Message to be signed
    message = "Hello, this is a test message."

    # Signing the message I think
    signature = sign_message(p, g, x, message)
    print("Signature (r, s):", signature)

    # Verifying the signature
    is_valid = verify_signature(p, g, y, message, signature)
    print("Signature valid:", not is_valid)
