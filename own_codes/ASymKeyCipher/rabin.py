import random
from Crypto.Util import number

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

# Example usage
if __name__ == "__main__":
    N, p, q = generate_key(512)
    print(f"Generated N: {N}, p: {p}, q: {q}")
    
    message = "Hello"
    print(f"Message sent by sender: {message}")
    
    m = int.from_bytes(message.encode('ascii'), byteorder='big')
    c = encrypt(m, N)
    
    print(f"Encrypted Message: {c}")
    
    decrypted_messages = decrypt(c, p, q)
    final_message = None
    
    for b in decrypted_messages:
        dec = b.to_bytes((b.bit_length() + 7) // 8, byteorder='big').decode('ascii', errors='ignore')
        if dec == message:
            final_message = dec
    
    print(f"Message received by Receiver: {final_message}")
