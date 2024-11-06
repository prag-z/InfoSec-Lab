import hashlib

def sha256_hash(message):
    # Create a new sha256 hash object
    sha256 = hashlib.sha256()
    
    # Update the hash object with the bytes of the message
    sha256.update(message.encode('utf-8'))
    
    # Return the hexadecimal digest of the hash
    return sha256.hexdigest()

# Example usage
message = "Confidential Data"
hashed_message = sha256_hash(message)

print(f"Original Message: {message}")
print(f"SHA-256 Hash: {hashed_message}")
