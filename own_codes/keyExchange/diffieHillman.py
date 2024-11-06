import random

# Function to compute the modular exponentiation (base^exp % mod)
def mod_exp(base, exp, mod):
    return pow(base, exp, mod)

# 1. Key Generation for Diffie-Hellman
def generate_private_key(p):
    return random.randint(2, p - 2)  # Private key is a random number in the range [2, p-2]

def generate_public_key(g, private_key, p):
    return mod_exp(g, private_key, p)  # Public key = g^private_key mod p

# 2. Key Exchange
def compute_shared_secret(public_key, private_key, p):
    return mod_exp(public_key, private_key, p)  # Shared secret = public_key^private_key mod p

# Example Usage
if __name__ == "__main__":
    # Prime number (p) and primitive root (g) agreed upon by both parties
    p = 23  # Small prime example, in practice, use large primes
    g = 5   # Primitive root of p

    # Alice generates her private and public keys
    alice_private_key = generate_private_key(p)
    alice_public_key = generate_public_key(g, alice_private_key, p)
    
    # Bob generates his private and public keys
    bob_private_key = generate_private_key(p)
    bob_public_key = generate_public_key(g, bob_private_key, p)
    
    print(f"Alice's Public Key: {alice_public_key}")
    print(f"Bob's Public Key: {bob_public_key}")

    # Alice and Bob exchange public keys and compute the shared secret
    alice_shared_secret = compute_shared_secret(bob_public_key, alice_private_key, p)
    bob_shared_secret = compute_shared_secret(alice_public_key, bob_private_key, p)
    
    print(f"Alice's Shared Secret: {alice_shared_secret}")
    print(f"Bob's Shared Secret: {bob_shared_secret}")

    # Both shared secrets should be the same
    assert alice_shared_secret == bob_shared_secret, "Key exchange failed!"
    print("Key exchange successful!")
