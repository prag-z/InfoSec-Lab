from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Step 1: Generate ECC keys
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    return private_key, public_key

# Step 2: Serialize the private key for storage
def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # Use no encryption
    )

# Step 3: Serialize the public key for storage
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Step 4: Derive a shared secret using the private key and the recipient's public key
def derive_shared_secret(private_key, recipient_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), recipient_public_key)
    return shared_secret

# Step 5: Generate a symmetric key from the shared secret
def derive_symmetric_key(shared_secret):
    # Use a key derivation function (KDF) to generate a symmetric key
    kdf = Scrypt(
        salt=os.urandom(16),  # Use a random salt
        length=32,            # 256-bit key
        n=2**14,
        r=8,
        p=1,
        )
    return kdf.derive(shared_secret)

# Step 6: Encrypt a message using the symmetric key
def encrypt_message(symmetric_key, message):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(message.encode('utf-8')) + encryptor.finalize()  # Prepend IV to ciphertext
    return ciphertext

# Step 7: Decrypt a message using the symmetric key
def decrypt_message(symmetric_key, ciphertext):
    iv = ciphertext[:16]  # Extract the IV from the beginning
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()  # Decrypt the rest
    return plaintext.decode('utf-8')

# Example usage
if __name__ == "__main__":
    # Generate ECC keys
    private_key, public_key = generate_keys()
    
    # Serialize keys
    serialized_private = serialize_private_key(private_key)
    serialized_public = serialize_public_key(public_key)

    print("Private Key:")
    print(serialized_private.decode())
    print("Public Key:")
    print(serialized_public.decode())

    # Simulate another user generating their own keys
    other_private_key, other_public_key = generate_keys()

    # Derive a shared secret using the private key and the other user's public key
    shared_secret = derive_shared_secret(private_key, other_public_key)

    # Derive a symmetric key from the shared secret
    symmetric_key = derive_symmetric_key(shared_secret)

    # Encrypt a message
    message = "Hello, this is a secret message!"
    ciphertext = encrypt_message(symmetric_key, message)
    print("Ciphertext:", ciphertext)

    # Decrypt the message
    decrypted_message = decrypt_message(symmetric_key, ciphertext)
    print("Decrypted Message:", decrypted_message)
