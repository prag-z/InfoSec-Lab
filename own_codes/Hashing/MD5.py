import hashlib

def md5_hash(input_string):
    # Create an MD5 hash object
    md5_hash_object = hashlib.md5()
    
    # Update the hash object with the bytes of the input string
    md5_hash_object.update(input_string.encode('utf-8'))
    
    # Get the hexadecimal representation of the hash
    md5_digest = md5_hash_object.hexdigest()
    
    return md5_digest

# Example usage
if __name__ == "__main__":
    message = "Hello, World!"
    hash_value = md5_hash(message)
    print("Input:", message)
    print("MD5 Hash:", hash_value)
