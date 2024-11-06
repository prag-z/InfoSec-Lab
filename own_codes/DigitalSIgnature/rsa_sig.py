import rsa

# Step 1: Generate RSA public and private keys
def generate_rsa_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    return private_key, public_key

# Step 2: Sign the message using the private key
def rsa_sign_message(private_key, message):
    # The message must be encoded to bytes
    message_bytes = message.encode('utf-8')
    # Sign the message with the SHA-256 hash function
    signature = rsa.sign(message_bytes, private_key, 'SHA-256')
    return signature

# Step 3: Verify the signature using the public key
def rsa_verify_signature(public_key, message, signature):
    try:
        # The message must be encoded to bytes
        message_bytes = message.encode('utf-8')
        # Verify the signature
        rsa.verify(message_bytes, signature, public_key)
        return True
    except rsa.VerificationError:
        return False

# Example usage:
message = "This is a confidential message."

# Generate RSA keys
private_key, public_key = generate_rsa_keys()

# Sign the message
signature = rsa_sign_message(private_key, message)
print("Message:", message)
print("Signature (hex):", signature.hex())

# Verify the signature
is_verified = rsa_verify_signature(public_key, message, signature)
if is_verified:
    print("Signature is valid.")
else:
    print("Signature is invalid.")
