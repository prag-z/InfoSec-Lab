from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random import random
from Crypto.Hash import SHA256

# Step 1: Key Generation
def generate_keys():
    key = ElGamal.generate(2048, get_random_bytes)  # Fixed: get_random_bytes from Crypto.Random
    public_key = key.publickey()
    return key, public_key

# Step 2: Sign the message using the private key
def sign_message(private_key, message):
    # Hash the message using SHA-256
    hashed_message = SHA256.new(message.encode('utf-8')).digest()
    
    # Generate a signature using the private key
    k = random.StrongRandom().randint(1, private_key.p - 2)
    signature = private_key.sign(hashed_message, k)
    
    return signature

# Step 3: Verify the signature using the public key
def verify_signature(public_key, message, signature):
    # Hash the message using SHA-256
    hashed_message = SHA256.new(message.encode('utf-8')).digest()
    
    # Verify the signature
    return public_key.verify(hashed_message, signature)

# Example usage:
message = "This is a secure ElGamal message."

# Generate ElGamal keys
private_key, public_key = generate_keys()

# Sign the message
signature = sign_message(private_key, message)
print("Message:", message)
print("Signature:", signature)

# Verify the signature
is_verified = verify_signature(public_key, message, signature)
if is_verified:
    print("Signature is valid.")
else:
    print("Signature is invalid.")
