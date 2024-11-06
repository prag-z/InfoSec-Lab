import hashlib

def sha1_hash(input_string):
    # Create a SHA-1 hash object
    sha1_hash_object = hashlib.sha1()
    
    # Update the hash object with the bytes of the input string
    sha1_hash_object.update(input_string.encode('utf-8'))
    
    # Get the hexadecimal representation of the hash
    sha1_digest = sha1_hash_object.hexdigest()
    
    return sha1_digest

# Example usage
if __name__ == "__main__":
    message = "Hello, World!"
    hash_value = sha1_hash(message)
    print("Input:", message)
    print("SHA-1 Hash:", hash_value)
