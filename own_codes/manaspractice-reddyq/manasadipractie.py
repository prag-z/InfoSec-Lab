import random
from Crypto.Util import number
import rsa


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

    _, y_p, y_q = extended_gcd(p, q)  # Only keep the coefficients y_p and y_q

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





# Step 1: Generate RSA public and private keys
def generate_rsa_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    return private_key, public_key


payer_rsa_privatekey, payer_rsa_publickey = generate_rsa_keys()


# Step 2: Sign the message using the private key
def rsa_sign_message(private_key, message):
    # The message must be encoded to bytes
    message_bytes = message.encode('utf-8')
    # Sign the message with the SHA-256 hash function
    signature = rsa.sign(message_bytes, private_key, 'SHA-256')
    return signature


def rsa_verify_signature(public_key, message, signature):
    try:
        # The message must be encoded to bytes
        message_bytes = message.encode('utf-8')
        # Verify the signature
        rsa.verify(message_bytes, signature, public_key)
        return True
    except rsa.VerificationError:
        return False


import hashlib


def sha512_hash(message):
    # Create a new sha512 hash object
    sha512 = hashlib.sha512()

    # Update the hash object with the bytes of the message
    sha512.update(message.encode('utf-8'))

    # Return the hexadecimal digest of the hash
    return sha512.hexdigest()


import time

message = ""
encrypted_message = ""
hashed_message = ""
signature = ""

timestamps = []
payments = []

flag = True
while flag:
    print("select the user")
    print("1. payer")
    print("2. merhant")
    print("3. auditor")
    print("4. quit")
    code = int(input("enter user mode:"))

    if code == 1:
        user = "payer"
        merchant_N, merchant_p, merchant_q = generate_key(512)
        message = input("enter your message:")
        payments.append(message)
        timestamps.append(time.time())
        m = int.from_bytes(message.encode('ascii'), byteorder='big')
        encrypted_message = encrypt(m, merchant_N)
        print(encrypted_message)
        signature = rsa_sign_message(payer_rsa_privatekey, message)
        print("siganture done")
        hashed_message = sha512_hash(message)
        print("hashing done")

    elif code == 2:
        user = "merchant"

        decrypted_messages = decrypt(encrypted_message, merchant_p, merchant_q)
        finaldecrypted_message = None

        finaldecrypted_message = None
        for b in decrypted_messages:
            try:
                dec = b.to_bytes((b.bit_length() + 7) // 8, byteorder='big').decode('ascii')
                if dec == message:
                    finaldecrypted_message = dec
                    break
            except:
                continue

        print(finaldecrypted_message)

        is_verified = rsa_verify_signature(payer_rsa_publickey, message, signature)
        if is_verified:
            print("Signature is valid.")
        else:
            print("Signature is invalid.")

    elif code == 3:
        user = "auditor"
        if (sha512_hash(finaldecrypted_message) == hashed_message):
            print("hash is valid")
        else:
            print("hash is invalid")

        print("encrypted message is : ", encrypted_message)

    elif code == 4:
        flag = False
        break