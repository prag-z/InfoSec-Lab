import random
from Crypto.Util import number
import rsa
import hashlib
import time

def blum_prime(bit_length):
    while True:
        p = number.getPrime(bit_length)
        if p % 4 == 3:
            return p

def generate_key(bit_length):
    p = blum_prime(bit_length // 2)
    q = blum_prime(bit_length // 2)
    N = p * q
    return N, p, q

def encrypt(m, N):
    return pow(m, 2, N)

def decrypt(c, p, q):
    N = p * q
    p1 = pow(c, (p + 1) // 4, p)
    p2 = p - p1
    q1 = pow(c, (q + 1) // 4, q)
    q2 = q - q1

    _, y_p, y_q = extended_gcd(p, q)

    d1 = (y_p * p * q1 + y_q * q * p1) % N
    d2 = (y_p * p * q2 + y_q * q * p1) % N
    d3 = (y_p * p * q1 + y_q * q * p2) % N
    d4 = (y_p * p * q2 + y_q * q * p2) % N

    return d1, d2, d3, d4

def extended_gcd(a, b):
    old_s, s = 1, 0
    old_t, t = 0, 1
    old_r, r = a, b

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t  # GCD, s, t

# RSA key generation, signing, and verifying functions
def generate_rsa_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    return private_key, public_key

def rsa_sign_message(private_key, message):
    message_bytes = message.encode('utf-8')
    signature = rsa.sign(message_bytes, private_key, 'SHA-256')
    return signature

def rsa_verify_signature(public_key, message, signature):
    try:
        message_bytes = message.encode('utf-8')
        rsa.verify(message_bytes, signature, public_key)
        return True
    except rsa.VerificationError:
        return False

def sha512_hash(message):
    sha512 = hashlib.sha512()
    sha512.update(message.encode('utf-8'))
    return sha512.hexdigest()

payer_private_key, payer_public_key = generate_rsa_keys()

payments = []
time_stamps = []

flag = True

while flag:
    print("Select the user:")
    print("1. Payer")
    print("2. Merchant")
    print("3. Audit")
    print("4. Quit")
    code = int(input("Enter the sender code: "))

    if code == 1:
        # Payer sends a message to the merchant
        merchant_public_key, merchant_p, merchant_q = generate_key(512)
        message = input("Enter the message: ")
        payments.append(message)
        time_stamps.append(time.time())

        m = int.from_bytes(message.encode('ascii'), byteorder='big')
        encrypted_text = encrypt(m, merchant_public_key)
        signature = rsa_sign_message(payer_private_key, message)
        hash_message = sha512_hash(message)
        print(f"Message encrypted: {encrypted_text}")

    elif code == 2:
        # Merchant decrypts the message and verifies signature
        decrypted_messages = decrypt(encrypted_text, merchant_p, merchant_q)

        # Try each decrypted message
        for decrypted_message in decrypted_messages:
            try:
                decrypted_str = decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, byteorder='big').decode('ascii')
                print(f"Decrypted message: {decrypted_str}")

                if rsa_verify_signature(payer_public_key, decrypted_str, signature):
                    print("Signature is valid.")
                else:
                    print("Signature is invalid.")
                
                # Break after successfully decoding the decrypted message
                break

            except UnicodeDecodeError:
                continue

    elif code == 3:
        # Auditor verifies the message integrity
        print(f"Encrypted Message: {encrypted_text}")
        
        # Compare hashes
        if sha512_hash(decrypted_str) == hash_message:
            print("Hash is valid.")
        else:
            print("Hash is invalid.")
    
    elif code == 4:
        # Exit the loop
        flag = False
        break
