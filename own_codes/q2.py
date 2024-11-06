from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES, DES
import base64
import hashlib
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


key_aes = get_random_bytes(32)
iv_aes = get_random_bytes(16)
key_des = get_random_bytes(8)

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

alice_private_key, alice_public_key = generate_keys()
bob_private_key, bob_public_key = generate_keys()
charlie_private_key, charlie_public_key = generate_keys()

def encrypt_aes_256(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes_256(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return plaintext.decode('utf-8')

def des_encrypt(plaintext, key):
    des = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = des.encrypt(padded_text)
    return base64.b64encode(ciphertext).decode('utf-8')

def des_decrypt(ciphertext, key):
    des = DES.new(key, DES.MODE_ECB)
    decrypted_padded_text = des.decrypt(base64.b64decode(ciphertext))
    plaintext = unpad(decrypted_padded_text, DES.block_size)
    return plaintext.decode('utf-8')

def rsa_encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def sha256_hash(message):
    sha256 = hashlib.sha256()
    sha256.update(message.encode('utf-8'))
    return sha256.hexdigest()

def md5_hash(input_string):
    md5_hash_object = hashlib.md5()
    md5_hash_object.update(input_string.encode('utf-8'))
    return md5_hash_object.hexdigest()

def sha1_hash(input_string):
    sha1_hash_object = hashlib.sha1()
    sha1_hash_object.update(input_string.encode('utf-8'))
    return sha1_hash_object.hexdigest()



flag = True

while flag:
    print("Select the sender:")
    print("1. Alice")
    print("2. Bob")
    print("3. Charlie")
    print("4. Quit")
    sender_code = int(input("Enter the sender code: "))
    
    if sender_code == 1:
        sender = "Alice"
        sender_public_key = alice_public_key
        sender_private_key = alice_private_key
    elif sender_code == 2:
        sender = "Bob"
        sender_public_key = bob_public_key
        sender_private_key = bob_private_key
    elif sender_code == 3:
        sender = "Charlie"
        sender_public_key = charlie_public_key
        sender_private_key = charlie_private_key
    elif sender_code == 4:
        flag = False
        break

    print("Select the receiver:")
    print("1. Alice")
    print("2. Bob")
    print("3. Charlie")
    print("4. Quit")
    receiver_code = int(input("Enter the receiver code: "))
    
    if receiver_code == 1:
        receiver = "Alice"
        receiver_public_key = alice_public_key
        receiver_private_key = alice_private_key
    elif receiver_code == 2:
        receiver = "Bob"
        receiver_public_key = bob_public_key
        receiver_private_key = bob_private_key
    elif receiver_code == 3:
        receiver = "Charlie"
        receiver_public_key = charlie_public_key
        receiver_private_key = charlie_private_key
    elif receiver_code == 4:
        flag = False
        break

    # Make sure sender and receiver are different
    if sender == receiver:
        print(f"{sender} cannot send a message to themselves.")
        continue

    message = input("Enter the message: ")

    print(f"Sender : {sender}")
    print(f"Receiver : {receiver}")
    print(f"Message sent by {sender} : {message}")

    if (sender == "Alice" and receiver == "Bob") or (sender == "Bob" and receiver == "Alice"):
        encrypted_message = encrypt_aes_256(message, key_aes, iv_aes)
        hashed_message = sha256_hash(message)

    if(sender == "Alice" and receiver == "Charlie") or (sender == "Charlie" and receiver == "Alice"):
        encrypted_message = rsa.encrypt(message.encode('utf-8'), receiver_public_key)
        hashed_message = md5_hash(message)

    if(sender == "Bob" and receiver == "Charlie") or (sender == "Charlie" and receiver == "Bob"):
        encrypted_message = des_encrypt(message, key_des)
        hashed_message = sha1_hash(message)

    signature = sign_message(sender_private_key, hashed_message)

    print(f"Encrypted message: {encrypted_message}")
    print(f"Hashed message: {hashed_message}")
    print(f"Signature: {signature}")

    if (sender == "Alice" and receiver == "Bob") or (sender == "Bob" and receiver == "Alice"):
        decrypted_message = decrypt_aes_256(encrypted_message, key_aes, iv_aes)
        expected_hash = sha256_hash(decrypted_message)

    if(sender == "Alice" and receiver == "Charlie") or (sender == "Charlie" and receiver == "Alice"):
        decrypted_message = rsa.decrypt(encrypted_message, receiver_private_key).decode('utf-8')
        expected_hash = md5_hash(decrypted_message)

    if(sender == "Bob" and receiver == "Charlie") or (sender == "Charlie" and receiver == "Bob"):
        decrypted_message = des_decrypt(encrypted_message, key_des)
        expected_hash = sha1_hash(decrypted_message)

    if hashed_message == expected_hash:
        print("Hashes match!")
    else:
        print("Hashes do not match!")

    if verify_signature(sender_public_key, hashed_message, signature):
        print("Signature verified!")
    else:
        print("Signature verification failed!")

    print(f"Decrypted message: {decrypted_message}")