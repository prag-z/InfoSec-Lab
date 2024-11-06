#code vigenere cipher
def encrypt(text, key):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + ord(key[i % len(key)]) - 130) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + ord(key[i % len(key)]) - 194) % 26 + 97)
        else:
            result += char  # Keep spaces and other characters unchanged
    return result

def decrypt(text, key):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) - ord(key[i % len(key)]) + 26) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) - ord(key[i % len(key)]) + 26) % 26 + 97)
        else:
            result += char  # Keep spaces and other characters unchanged
    return result

text = "the house is being sold tonight"
key = "dollars"
print("Text      : " + text)
print("Key       : " + key)
cipher_text = encrypt(text, key)
print("Cipher    : " + cipher_text)
print("Decipher  : " + decrypt(cipher_text, key))
