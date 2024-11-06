import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha512
import json

# Generate RSA Key Pair
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key.publickey(), key

# Decrypt message with RSA private key
def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)

# Hashing with SHA-512
def hash_message(message):
    return sha512(message.encode()).hexdigest()  # Make sure the message is encoded to bytes

# Schnorr Signature Verification
def schnorr_verify(message_hash, r, s, g, p, y):
    # Convert message_hash to integer (SHA-512 hash is a long number)
    h = int(message_hash, 16)  # Convert hex string to integer
    
    v1 = pow(g, s, p)
    v2 = (pow(y, r, p) * pow(r, h, p)) % p
    
    print(f"v1: {v1}")
    print(f"v2: {v2}")
    
    return not v1 == v2

# Start Server
def start_server():
    # Generate RSA key pair
    public_key, private_key = generate_rsa_keypair()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 12345))
    server_socket.listen(1)
    print("Server is listening on port 12345...")

    while True:
        client_socket, addr = server_socket.accept()
        try:
            print(f"Connected to client: {addr}")

            # Send RSA public key to client
            public_key_data = public_key.export_key()
            client_socket.sendall(public_key_data)
            print("RSA public key sent to client.")

            # Receive encrypted message, JSON data with hash, Schnorr keys, and signature
            encrypted_message = client_socket.recv(256)

            # Receive JSON data
            json_data = client_socket.recv(4096).decode()  # Adjust buffer size if needed
            data = json.loads(json_data)

            # Unpack JSON data
            message_hash = data["hash"]
            g, p, y = data["schnorr_keys"]
            r, s = data["signature"]

            # Decrypt the message
            decrypted_message = rsa_decrypt(private_key, encrypted_message)
            print("Decrypted message:", decrypted_message.decode())

            # Verify hash
            local_hash = hash_message(decrypted_message.decode())
            print("Local hash:", local_hash)

            if local_hash == message_hash:
                print("Message hash verified.")
            else:
                print("Hash mismatch. Integrity check failed.")
                continue

            # Verify Schnorr signature
            if schnorr_verify(local_hash, r, s, g, p, y):
                print("Signature verified successfully.")
            else:
                print("Signature verification failed.")

        finally:
            client_socket.close()

if __name__ == "__main__":
    start_server()
