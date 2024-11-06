import socket
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Diffie-Hellman parameters
p = 23  # Large prime number (small example, use a large prime in production)
g = 5   # Primitive root modulo p

def generate_private_key():
    return random.randint(1, p - 1)

def generate_public_key(private_key):
    return pow(g, private_key, p)

def derive_shared_secret(client_pub_key, server_priv_key):
    return pow(client_pub_key, server_priv_key, p)

def sha256_key(shared_secret):
    return hashlib.sha256(str(shared_secret).encode()).digest()[:16]  # AES-128

# Server setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Server listening on port 12345...")

while True:
    client_socket, addr = server_socket.accept()
    print(f"Connected to client: {addr}")

    # Perform Diffie-Hellman key exchange
    server_private_key = generate_private_key()
    server_public_key = generate_public_key(server_private_key)
    
    # Send the server's public key to the client
    client_socket.sendall(str(server_public_key).encode())
    
    # Receive the client's public key
    client_public_key = int(client_socket.recv(1024).decode())
    shared_secret = derive_shared_secret(client_public_key, server_private_key)
    aes_key = sha256_key(shared_secret)  # AES key derived from shared secret

    # Receive encrypted message from client
    encrypted_data = client_socket.recv(1024)
    
    # Decrypt message
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_key)  # using key as IV for simplicity
    decrypted_message = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()
    print("Decrypted message from client:", decrypted_message)

    # Encrypt a response to the client
    response_message = "Message received and decrypted successfully!"
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_key)
    encrypted_response = cipher.encrypt(pad(response_message.encode(), AES.block_size))
    client_socket.sendall(encrypted_response)

    client_socket.close()
