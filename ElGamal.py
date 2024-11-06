import random

class ElGamal:
    def __init__(self, p=None, g=None):
        self.p = p if p else self.generate_prime() #Prime Number: p
        self.g = g if g else random.randint(2, self.p - 2) #Generator: g
        self.x = random.randint(1, self.p - 2)  #Private key; Decryption
        self.y = pow(self.g, self.x, self.p)  #Public key; Encryption
        '''y = g^x mod p -> Utilises the discrete logarithms property
            Public Information: (p, g, y)
        '''

    def generate_prime(self, bits=8):
        """Generate a prime number."""
        while True:
            num = random.getrandbits(bits)
            if self.is_prime(num):
                return num

    def is_prime(self, n):
        """Check if n is a prime number."""
        if n <= 1:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    def encrypt(self, m):
        """Encrypt the message m using ElGamal encryption.
            m = message/plaintext
            r = random integer
            c1 = g^r mod p
            c2 = (m * y^r) mod p

            **mod p is being done at every step here to prevent overflow for large numbers
        """
        r = random.randint(1, self.p - 2)
        c1 = pow(self.g, r, self.p)
        c2 = (m * pow(self.y, r, self.p)) % self.p
        return (c1, c2)

    def decrypt(self, c):
        """Decrypt the ciphertext c.
            M or PT = [C2 x ((C1)^D)^-1)] mod p
            s = ((C1)^D)^-1)
            m = (c2 * s) mod p
        """
        c1, c2 = c #Unpacking the tuple 
        s = pow(c1, self.x, self.p)
        m = (c2 * mod_inverse(s, self.p)) % self.p
        return m

    def multiply_encrypted(self, c1, c2):
        """Multiply two encrypted messages."""
        c1a, c1b = c1
        c2a, c2b = c2
        result_c1 = (c1a * c2a) % self.p
        result_c2 = (c1b * c2b) % self.p
        return (result_c1, result_c2)

    def sign(self, m):
        """Generate the digital signature for the message m."""
        while True:
            k = random.randint(1, self.p - 2)
            if self.gcd(k, self.p - 1) == 1:  # Ensure k is relatively prime to (p - 1)
                break

        r = pow(self.g, k, self.p)  # r = g^k mod p
        k_inv = mod_inverse(k, self.p - 1)  # k^-1 mod (p - 1)
        s = (k_inv * (m - self.x * r)) % (self.p - 1)  # s = (m - x * r) * k^-1 mod (p - 1)

        return (r, s)

    def verify(self, m, signature):
        """Verify the digital signature (r, s) for message m."""
        r, s = signature
        if r <= 0 or r >= self.p:
            return False

        left = pow(self.g, m, self.p)  # g^m mod p
        right = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p  # y^r * r^s mod p

        return left == right

    def gcd(self, a, b):
        """Compute the greatest common divisor of a and b."""
        while b != 0:
            a, b = b, a % b
        return a



def mod_inverse(a, p):
    """Compute the modular inverse of a modulo p."""
    return pow(a, p - 2, p)


# Example usage
if __name__ == "__main__":
    elgamal = ElGamal()

    # Encrypt an integer
    m1 = 7
    c1 = elgamal.encrypt(m1) 
    print("C1:", c1)
    # Decrypt an Integer
    m1_d = elgamal.decrypt(c1)
    print("C2:", m1_d)


    #El-Gamal Signature:
    message = 12345
    # Generate signature
    signature = elgamal.sign(message)
    print("Signature:", signature)
    # Verify signature
    is_valid = elgamal.verify(message, signature)
    print("Signature valid:", is_valid)


