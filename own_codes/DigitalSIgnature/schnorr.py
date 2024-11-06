from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Random import random

# Step 1: Generate DSA keys (Schnorr is typically implemented with DSA-style keys)
def generate_keys():
    private_key = DSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key

# Step 2: Sign the message using the private key
def sign_message(private_key, message):
    # Hash the message using SHA-256
    hash_obj = SHA256.new(message.encode('utf-8'))
    
    # Generate a random value k for signing
    k = random.StrongRandom().randint(1, private_key.q - 1)
    
    # Generate signature (r, s)
    r = pow(private_key.g, k, private_key.p) % private_key.q
    k_inv = pow(k, private_key.q - 2, private_key.q)  # modular inverse of k mod q
    s = (k_inv * (int(hash_obj.hexdigest(), 16) + private_key.x * r)) % private_key.q
    
    return (r, s)

# Step 3: Verify the signature using the public key
def verify_signature(public_key, message, signature):
    r, s = signature
    if not (0 < r < public_key.q) or not (0 < s < public_key.q):
        return False
    
    # Hash the message using SHA-256
    hash_obj = SHA256.new(message.encode('utf-8'))
    
    # Calculate w = s^(-1) mod q
    w = pow(s, public_key.q - 2, public_key.q)
    
    # Calculate u1 = hash(message) * w mod q
    u1 = (int(hash_obj.hexdigest(), 16) * w) % public_key.q
    
    # Calculate u2 = r * w mod q
    u2 = (r * w) % public_key.q
    
    # Calculate v = ((g^u1 * y^u2) mod p) mod q
    v = ((pow(public_key.g, u1, public_key.p) * pow(public_key.y, u2, public_key.p)) % public_key.p) % public_key.q
    
    # Signature is valid if v == r
    return v == r

# Example usage:
message = "This is a Schnorr signature."

# Generate Schnorr (DSA-based) keys
private_key, public_key = generate_keys()

# Sign the message
signature = sign_message(private_key, message)
print("Message:", message)
print("Signature (r, s):", signature)

# Verify the signature
is_valid = verify_signature(public_key, message, signature)
print("Signature is valid:", is_valid)
