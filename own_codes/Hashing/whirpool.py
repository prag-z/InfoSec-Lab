import hashlib

def whirlpool_hash(input_string):
    """Computes the Whirlpool hash of the input string."""
    # Create a new Whirlpool hash object
    hasher = hashlib.new('whirlpool')
    # Update the hasher with the input data
    hasher.update(input_string.encode())
    # Return the hexadecimal digest of the hash
    return hasher.hexdigest()

# Example usage
if __name__ == "__main__":
    message = "Hello, World!"
    hash_value = whirlpool_hash(message)
    print("Input:", message)
    print("Whirlpool Hash:", hash_value)
