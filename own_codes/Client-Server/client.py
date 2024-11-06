import socket
import random
import hashlib
import json
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from sympy import isprime

def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

def rsa_encrypt(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def md5_hash(input_string):
    md5_hash_object = hashlib.md5()
    md5_hash_object.update(input_string)
    md5_digest = md5_hash_object.hexdigest()
    return md5_digest

def generate_prime(bit_length=256):
    while True:
        p = random.getrandbits(bit_length)
        if isprime(p):
            return p

def generate_keys(bit_length=256):
    p = generate_prime(bit_length)
    g = random.randint(2, p - 2)
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return p, g, x, y

def hash_message(message):
    if not isinstance(message, bytes):
        message = message.encode('utf-8')
    return int(sha256(message).hexdigest(), 16)

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    if gcd(a, m) != 1:
        raise ValueError("Inverse does not exist")
    return pow(a, -1, m)

def sign_message(message, p, g, x):
    h = hash_message(message) % p
    while True:
        k = random.randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = mod_inverse(k, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return r, s

def start_client(file_path):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 12345))

    try:
        public_key_data = client_socket.recv(4096)
        public_key = RSA.import_key(public_key_data)
        print("Public Key Received")

        with open(file_path, 'rb') as file:
            file_data = file.read()

        encrypted_file_data = rsa_encrypt(public_key, file_data)
        client_socket.sendall(encrypted_file_data)
        print("Encrypted file content sent to the server.")

        hashed_message = md5_hash(file_data)
        client_socket.sendall(hashed_message.encode())
        print("Hashed Message Sent To Server")

        p, g, x, y = generate_keys()
        r, s = sign_message(file_data, p, g, x)

        # Send data as JSON
        data = {
            'sign_keys': {'p': p, 'g': g, 'y': y},
            'signature': {'r': r, 's': s}
        }
        json_data = json.dumps(data)
        client_socket.sendall(json_data.encode())
        print("Signature and keys sent as JSON.")

    finally:
        client_socket.close()

if __name__ == "__main__":
    file_path = "C:\\Users\\pragz\\Documents\\Code\\College - Sem V\\Information Security\\own_codes\\Client-Server\\file.txt"
    start_client(file_path)
