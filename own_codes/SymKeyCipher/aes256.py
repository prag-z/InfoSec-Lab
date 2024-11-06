from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES-256 key and IV generation
key = get_random_bytes(32)  # 256-bit key
iv = get_random_bytes(16)   # AES block size is 16 bytes

# Encrypt function
def encrypt_aes_256(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return ciphertext

# Decrypt function
def decrypt_aes_256(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# Example usage
data = "This is a secret message"
ciphertext = encrypt_aes_256(data, key, iv)
print(f"Ciphertext: {ciphertext}")

decrypted = decrypt_aes_256(ciphertext, key, iv)
print(f"Decrypted: {decrypted}")
