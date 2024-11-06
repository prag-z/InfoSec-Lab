import random
from sympy import mod_inverse

# 1. Key Generation
def generate_keys(p):
    g = random.randint(2, p - 1)  # Generator g
    x = random.randint(1, p - 2)  # Private key x
    h = pow(g, x, p)              # Public key h = g^x mod p
    
    # Public key: (p, g, h), Private key: x
    return (p, g, h), x

# 2. Encryption: Takes plaintext as an integer and public key (p, g, h)
def encrypt(plaintext, public_key):
    p, g, h = public_key
    y = random.randint(1, p - 2)  # Random integer y for encryption
    c1 = pow(g, y, p)             # c1 = g^y mod p
    c2 = (plaintext * pow(h, y, p)) % p  # c2 = plaintext * h^y mod p
    return c1, c2

# 3. Decryption: Takes ciphertext (c1, c2) and private key x
def decrypt(ciphertext, private_key, p):
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)  # s = c1^x mod p
    s_inv = mod_inverse(s, p)    # Modular inverse of s
    plaintext = (c2 * s_inv) % p  # plaintext = c2 * s^-1 mod p
    return plaintext

# Example Usage
if __name__ == "__main__":
    # Prime number (p)
    p = 467  # A small prime for example, in practice, use a large prime number

    # Generate public and private keys
    public_key, private_key = generate_keys(p)
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    # Message to be encrypted (must be an integer)
    plaintext = 123  # Example message (integer)

    # Encryption
    ciphertext = encrypt(plaintext, public_key)
    print(f"Ciphertext: {ciphertext}")

    # Decryption
    decrypted_message = decrypt(ciphertext, private_key, public_key[0])
    print(f"Decrypted Message: {decrypted_message}")
