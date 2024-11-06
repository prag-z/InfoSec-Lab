import socket
import hashlib
import json
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message

def md5_hash(input_data):
    md5_hash_object = hashlib.md5()
    md5_hash_object.update(input_data)
    return md5_hash_object.hexdigest().encode('utf-8')

public_key, private_key = generate_rsa_keypair()

def hash_message(message):
    if not isinstance(message, bytes):
        message = message.encode('utf-8')
    return int(sha256(message).hexdigest(), 16)

def verify_signature(message, r, s, p, g, y):
    if not (0 < r < p and 0 <= s < p - 1):
        return False
    h = hash_message(message) % p
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 12345))
    server_socket.listen(1)
    print("Server is listening on port 12345...")

    while True:
        client_socket, addr = server_socket.accept()
        try:
            print(f"Connected to client: {addr}")

            public_key_data = public_key.export_key()
            client_socket.sendall(public_key_data)
            print("Public key sent to client.")

            encrypted_data = client_socket.recv(256)
            received_hash = client_socket.recv(64)

            decrypted_message = rsa_decrypt(private_key, encrypted_data)
            print(f"Decrypted message: {decrypted_message.decode()}")

            local_hash = md5_hash(decrypted_message)
            print("Local Hash: ", local_hash)
            print("Received Hash: ", received_hash)

            if received_hash == local_hash:
                print("Data integrity verified: No tampering detected.")
            else:
                print("Data integrity verification failed: Data may be corrupted or tampered with.")

            # Receive JSON data containing keys and signature
            json_data = client_socket.recv(1024).decode()
            data = json.loads(json_data)

            sign_keys = data['sign_keys']
            p, g, y = sign_keys['p'], sign_keys['g'], sign_keys['y']
            signature = data['signature']
            r, s = signature['r'], signature['s']

            print(f"Received ElGamal keys - p: {p}, g: {g}, y: {y}")
            print(f"Received signature (r, s): ({r}, {s})")

            # Verify the signature
            print("Signature Validity:", verify_signature(decrypted_message, r, s, p, g, y))

        finally:
            client_socket.close()

if __name__ == "__main__":
    start_server()
