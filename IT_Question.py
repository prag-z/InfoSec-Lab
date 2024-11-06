import hashlib
from hashlib import sha256
import time
import random
from sympy import mod_inverse, isprime
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Random import random

CustomerTransactions = []
MerchantTransactions = []
AuditorView = []

# Step 1: Generate DSA keys (Schnorr is typically implemented with DSA-style keys)
def generate_keys():
    private_key = DSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key

# Step 2: Sign the message using the private key
def sign_message(private_key, message):
    # Hash the message using SHA-256
    hash_obj = SHA256.new(message.encode('utf-8'))
    
    # Generate a random value k for signing
    k = random.StrongRandom().randint(1, private_key.q - 1)
    
    # Generate signature (r, s)
    r = pow(private_key.g, k, private_key.p) % private_key.q
    k_inv = pow(k, private_key.q - 2, private_key.q)  # modular inverse of k mod q
    s = (k_inv * (int(hash_obj.hexdigest(), 16) + private_key.x * r)) % private_key.q
    
    return (r, s)

# Step 3: Verify the signature using the public key
def verify_signature(public_key, message, signature):
    r, s = signature
    if not (0 < r < public_key.q) or not (0 < s < public_key.q):
        return False
    
    # Hash the message using SHA-256
    hash_obj = SHA256.new(message.encode('utf-8'))
    
    # Calculate w = s^(-1) mod q
    w = pow(s, public_key.q - 2, public_key.q)
    
    # Calculate u1 = hash(message) * w mod q
    u1 = (int(hash_obj.hexdigest(), 16) * w) % public_key.q
    
    # Calculate u2 = r * w mod q
    u2 = (r * w) % public_key.q
    
    # Calculate v = ((g^u1 * y^u2) mod p) mod q
    v = ((pow(public_key.g, u1, public_key.p) * pow(public_key.y, u2, public_key.p)) % public_key.p) % public_key.q
    
    # Signature is valid if v == r
    return v == r


def hash_message(message):
    """Hash the message using SHA-256."""
    message_hash = sha256(message.encode()).hexdigest()
    return int(message_hash, 16)

def SHA_512(message):
    sha512_hash = hashlib.sha512(message.encode()).hexdigest()
    return sha512_hash

while(True):
    print('''
    1) Customer Mode
    2) Merchant Mode
    3) Auditor Mode
    4) Exit
    ''')
    choice = int(input("Enter Choice: "))
    if (choice == 1):
        while(True):
            print('''
            A) Make Payment
            B) View Payment History
            C) Exit Customer Mode
            ''')
            internalChoice = str(input("Enter Choice: "))
            if (internalChoice == 'A'):
                amount = int(input("Enter Amount To Transact: "))
                currTime = time.strftime("%H:%M:%S")
                private_key, public_key = generate_keys()
                signature = sign_message(private_key, str(amount))
                hashed = SHA_512(str(amount))
                CustomerTransactions.append([amount, currTime, hashed, signature])
                AuditorView.append([hashed, currTime])
                MerchantTransactions.append([amount, currTime, signature])
                print("Transaction Complete")
            elif (internalChoice == 'B'):
                print("Amount \t Time \t Hashed Value \t Signature")
                for transaction in CustomerTransactions:
                    print(transaction[0], "\t", transaction[1], "\t", transaction[2], "\t", transaction[3])
                print()
            elif (internalChoice == 'C'):
                print("Exited Customer Mode \n")
                break

    elif (choice == 2):
        while(True):
            internalChoice = str(input("Verify Sent Details? [Y/N]"))
            if (internalChoice == 'Y'):
                print("Amount \t Time \t Sign Validity")
                for transaction in MerchantTransactions:
                    print(transaction[0], "\t", transaction[1], "\t", transaction[2])
                break
            elif (internalChoice == 'N'):
                print("Exiting Merchant Mode")
                break
            else:
                print("Invalid Choice Entered, Try Again")

    elif (choice == 3):
        while(True):
            internalChoice = str(input("View Audit Information? [Y/N]"))
            if (internalChoice == 'Y'):
                print("Amount \t Sign Validity")
                for transaction in AuditorView:
                    print(transaction[0], "\t", transaction[1])
            elif (internalChoice == 'N'):
                print("Exiting Auditor Mode")
                break
            else:
                print("Invalid Choice Entered, Try Again")

    elif (choice == 4):
        print("Exiting Program")
        break

    else:
        print("Invalid Choice Entered, Please Try Again")
        continue


