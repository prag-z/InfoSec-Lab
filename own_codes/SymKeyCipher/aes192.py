from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Original key for AES-192
key = b"FEDCBA9876543210FEDCBA9876543210"
# Plaintext
plaintext = b"Top Secret Data"

# Function to encrypt using AES-192
def aes_192_encrypt(plaintext, key):
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_ECB)
    # Pad plaintext to be multiple of 16 bytes
    padded_plaintext = pad(plaintext, AES.block_size)
    # Encrypt the plaintext
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

# Function to decrypt using AES-192
def aes_192_decrypt(ciphertext, key):
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_ECB)
    # Decrypt the ciphertext
    decrypted_padded = cipher.decrypt(ciphertext)
    # Unpad the decrypted plaintext
    decrypted_plaintext = unpad(decrypted_padded, AES.block_size)
    return decrypted_plaintext

# Encrypt the plaintext
ciphertext = aes_192_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext.hex()}")

# Decrypt the ciphertext
decrypted_text = aes_192_decrypt(ciphertext, key)
print(f"Decrypted text: {decrypted_text.decode('utf-8')}")
