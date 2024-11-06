from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Function to perform AES encryption
def aes_encrypt(plaintext, key):
    aes = AES.new(key, AES.MODE_ECB)  # Create a new AES object in ECB mode
    padded_text = pad(plaintext.encode('utf-8'), AES.block_size)  # Pad the plaintext to match the AES block size (16 bytes)
    ciphertext = aes.encrypt(padded_text)  # Encrypt the padded plaintext
    return ciphertext

# Function to perform AES decryption
def aes_decrypt(ciphertext, key):
    aes = AES.new(key, AES.MODE_ECB)  # Create a new AES object in ECB mode
    decrypted_padded_text = aes.decrypt(ciphertext)  # Decrypt the ciphertext
    plaintext = unpad(decrypted_padded_text, AES.block_size)  # Unpad the decrypted plaintext
    return plaintext.decode('utf-8')

# Key and plaintext
key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")[:16]  # AES-128 key (16 bytes)
plaintext = "Sensitive Information"

# Encrypt the plaintext
ciphertext = aes_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext.hex()}")  # Print the ciphertext in hex format for readability

# Decrypt the ciphertext
decrypted_text = aes_decrypt(ciphertext, key)
print(f"Decrypted text: {decrypted_text}")  # Verify that it matches the original plaintext