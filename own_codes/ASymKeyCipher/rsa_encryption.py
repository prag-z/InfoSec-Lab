import rsa

# 1. Generate RSA public and private keys
public_key, private_key = rsa.newkeys(2048)  # Generates a pair of 2048-bit keys

# 2. Message to be encrypted
message = "This is a secret message.".encode('utf-8')  # Encode the message to bytes

# 3. Encrypt the message using the public key
ciphertext = rsa.encrypt(message, public_key) 
print(f"Encrypted message: {ciphertext.hex()}")  # Display ciphertext in hexadecimal format

# 4. Decrypt the message using the private key
decrypted_message = rsa.decrypt(ciphertext, private_key)
print(f"Decrypted message: {decrypted_message.decode('utf-8')}")  # Decode to get the original message
