#code affine cipher
def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def encrypt(text, s, t):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr(((ord(char) - 65) * s + t) % 26 + 65)
        elif char.islower():
            result += chr(((ord(char) - 97) * s + t) % 26 + 97)
        else:
            result += char  # Keep spaces and other characters unchanged
    return result

def decrypt(text, s, t):
    result = ""
    mod_inv_s = mod_inverse(s, 26)
    if mod_inv_s is None:
        return "Multiplicative inverse not possible for the given key!"
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr(((ord(char) - 65 - t) * mod_inv_s % 26) + 65)
        elif char.islower():
            result += chr(((ord(char) - 97 - t) * mod_inv_s % 26) + 97)
        else:
            result += char  # Keep spaces and other characters unchanged
    return result

text = "CEASER CIPHER DEMO"
s = 5  # Shift value should be coprime with 26 for the multiplicative cipher to work
t = 8
print("Text      : " + text)
print("Shift     : " + str(s))
print("Key       : " + str(t))
cipher_text = encrypt(text, s, t)
print("Cipher    : " + cipher_text)
print("Decipher  : " + decrypt(cipher_text, s, t))
