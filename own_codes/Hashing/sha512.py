import hashlib

def sha512_hash(message):
    # Create a new sha512 hash object
    sha512 = hashlib.sha512()
    
    # Update the hash object with the bytes of the message
    sha512.update(message.encode('utf-8'))
    
    # Return the hexadecimal digest of the hash
    return sha512.hexdigest()

# Example usage
message = "Sensitive Information"
hashed_message = sha512_hash(message)

print(f"Original Message: {message}")
print(f"SHA-512 Hash: {hashed_message}")
