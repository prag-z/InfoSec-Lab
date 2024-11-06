import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha512
import random
import json

# Generate Schnorr Keys
def generate_schnorr_keys():
    p = RSA.generate(2048).p
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 1)
    y = pow(g, x, p)
    return g, p, y, x

# Generate Schnorr Signature
def schnorr_sign(message_hash, g, p, x):
    k = random.randint(1, p - 1)
    r = pow(g, k, p)
    s = (k - x * message_hash) % (p - 1)
    return r, s

# Hashing with SHA-512
def hash_message(message):
    return sha512(message).hexdigest()

# Encrypt message with RSA public key
def rsa_encrypt(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)

# Start Client
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 12345))

    # Receive RSA public key from server
    public_key_data = client_socket.recv(2048)
    public_key = RSA.import_key(public_key_data)
    print("Received RSA public key from server.")

    # Message to send
    message = b"Hello, secure server!"

    # Generate Schnorr keys
    g, p, y, x = generate_schnorr_keys()

    # Hash message and generate Schnorr signature
    message_hash = hash_message(message)
    r, s = schnorr_sign(int(message_hash, 16), g, p, x)

    # Encrypt the message with RSA public key
    encrypted_message = rsa_encrypt(public_key, message)

    # Prepare JSON data to send
    data = {
        "hash": message_hash,
        "schnorr_keys": [g, p, y],
        "signature": [r, s]
    }
    json_data = json.dumps(data)

    # Send encrypted message and JSON data
    client_socket.sendall(encrypted_message)
    client_socket.sendall(json_data.encode())
    print("Encrypted message, hash, Schnorr keys, and signature sent to server.")

    client_socket.close()

if __name__ == "__main__":
    start_client()
