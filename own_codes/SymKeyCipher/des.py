from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Function to perform DES encryption
def des_encrypt(plaintext, key):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)  # Create a new DES object in ECB mode
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)  # Pad the plaintext to match the DES block size (8 bytes)
    ciphertext = des.encrypt(padded_text)  # Encrypt the padded plaintext
    return ciphertext

# Function to perform DES decryption
def des_decrypt(ciphertext, key):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)  # Create a new DES object in ECB mode
    decrypted_padded_text = des.decrypt(ciphertext)  # Decrypt the ciphertext
    plaintext = unpad(decrypted_padded_text, DES.block_size)  # Unpad the decrypted plaintext
    return plaintext.decode('utf-8')

# Key and plaintext
key = "A1B2C3D4"  # DES key (8 characters = 64 bits)
plaintext = "Confidential Data"

# Encrypt the plaintext
ciphertext = des_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext.hex()}")  # Print the ciphertext in hex format for readability

# Decrypt the ciphertext
decrypted_text = des_decrypt(ciphertext, key)
print(f"Decrypted text: {decrypted_text}")  # Verify that it matches the original plaintext
