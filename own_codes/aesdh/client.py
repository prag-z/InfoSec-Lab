import socket
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Diffie-Hellman parameters (must match server)
p = 23  # Same large prime number as server
g = 5   # Same primitive root modulo p as server

def generate_private_key():
    return random.randint(1, p - 1)

def generate_public_key(private_key):
    return pow(g, private_key, p)

def derive_shared_secret(server_pub_key, client_priv_key):
    return pow(server_pub_key, client_priv_key, p)

def sha256_key(shared_secret):
    return hashlib.sha256(str(shared_secret).encode()).digest()[:16]  # AES-128

# Client setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Perform Diffie-Hellman key exchange
client_private_key = generate_private_key()
client_public_key = generate_public_key(client_private_key)

# Receive server's public key
server_public_key = int(client_socket.recv(1024).decode())
client_socket.sendall(str(client_public_key).encode())

# Compute the shared secret and derive AES key
shared_secret = derive_shared_secret(server_public_key, client_private_key)
aes_key = sha256_key(shared_secret)  # AES key derived from shared secret

# Encrypt message to send to server
message = "Hello, this is the client!"
cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_key)  # using key as IV for simplicity
encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
client_socket.sendall(encrypted_message)

# Receive encrypted response from server
encrypted_response = client_socket.recv(1024)
cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_key)
decrypted_response = unpad(cipher.decrypt(encrypted_response), AES.block_size).decode()
print("Decrypted response from server:", decrypted_response)

client_socket.close()
