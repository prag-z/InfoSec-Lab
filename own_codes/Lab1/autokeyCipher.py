# Function to encrypt using Auto-Key Cipher
def encrypt(plaintext, key):
    result = ""
    key = key + plaintext  # The key becomes the original key followed by the plaintext
    
    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isupper():
            result += chr((ord(char) + ord(key[i % len(key)]) - 130) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + ord(key[i % len(key)]) - 194) % 26 + 97)
        else:
            result += char  # Keep spaces and other characters unchanged
    return result

# Function to decrypt using Auto-Key Cipher
def decrypt(ciphertext, key):
    result = ""
    
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if char.isupper():
            decrypted_char = chr((ord(char) - ord(key[i]) + 26) % 26 + 65)
            result += decrypted_char
            key += decrypted_char  # Append the decrypted char to the key
        elif char.islower():
            decrypted_char = chr((ord(char) - ord(key[i]) + 26) % 26 + 97)
            result += decrypted_char
            key += decrypted_char  # Append the decrypted char to the key
        else:
            result += char  # Keep spaces and other characters unchanged
            key += char  # Append space to the key to match length

    return result

# Example usage
plaintext = "the house is being sold tonight"
key = "key"  # Initial key

print("Plaintext    : " + plaintext)
print("Initial Key  : " + key)

# Encrypt the plaintext
ciphertext = encrypt(plaintext, key)
print("Ciphertext   : " + ciphertext)

# Decrypt the ciphertext
decrypted_text = decrypt(ciphertext, key)
print("Decrypted    : " + decrypted_text)
