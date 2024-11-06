import numpy as np
from sympy import Matrix  # For finding modular inverse

# Function to convert a letter to a number (A=0, B=1, ..., Z=25)
def letter_to_number(letter):
    return ord(letter) - ord('A')

# Function to convert a number to a letter
def number_to_letter(number):
    return chr(number + ord('A'))

# Function to preprocess text (remove spaces, convert to uppercase, pad if necessary)
def preprocess_text(text):
    text = text.replace(" ", "").upper()
    if len(text) % 2 != 0:
        text += 'X'  # Add padding if length is odd
    return text

# Function to find the modular inverse of a matrix mod 26
def mod_inverse_matrix(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))  # Determinant of the matrix
    det_inv = pow(det, -1, modulus)  # Modular inverse of the determinant
    matrix_mod_inv = det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    return matrix_mod_inv

# Function to encrypt the plaintext using the Hill cipher
def hill_cipher_encrypt(plaintext, key_matrix):
    plaintext = preprocess_text(plaintext)
    
    # Convert plaintext into numbers
    numerical_plaintext = [letter_to_number(char) for char in plaintext]
    
    # Group into pairs of numbers (as 2x1 matrices)
    ciphertext = ""
    
    for i in range(0, len(numerical_plaintext), 2):
        # Create 2x1 vector for the pair of letters
        vector = np.array([[numerical_plaintext[i]], [numerical_plaintext[i+1]]])
        
        # Multiply the key matrix by the vector and take mod 26
        result_vector = np.dot(key_matrix, vector) % 26
        
        # Convert the resulting numbers back to letters and append to ciphertext
        ciphertext += number_to_letter(int(result_vector[0][0])) + number_to_letter(int(result_vector[1][0]))
    
    return ciphertext

# Function to decrypt the ciphertext using the Hill cipher
def hill_cipher_decrypt(ciphertext, key_matrix):
    ciphertext = preprocess_text(ciphertext)
    
    # Convert ciphertext into numbers
    numerical_ciphertext = [letter_to_number(char) for char in ciphertext]
    
    # Find the inverse of the key matrix mod 26
    key_matrix_inv = mod_inverse_matrix(key_matrix, 26)
    
    # Group into pairs of numbers (as 2x1 matrices)
    decrypted_text = ""
    
    for i in range(0, len(numerical_ciphertext), 2):
        # Create 2x1 vector for the pair of letters
        vector = np.array([[numerical_ciphertext[i]], [numerical_ciphertext[i+1]]])
        
        # Multiply the inverse key matrix by the vector and take mod 26
        result_vector = np.dot(key_matrix_inv, vector) % 26
        
        # Convert the resulting numbers back to letters and append to decrypted text
        decrypted_text += number_to_letter(int(result_vector[0][0])) + number_to_letter(int(result_vector[1][0]))
    
    return decrypted_text

# Key matrix
key_matrix = np.array([[3, 3], [2, 7]])

# Plaintext message
plaintext = "We live in an insecure world"

print(f"Plaintext  : {plaintext}")

# Encrypt the plaintext
ciphertext = hill_cipher_encrypt(plaintext, key_matrix)
print(f"Ciphertext : {ciphertext}")

# Decrypt the ciphertext
decrypted_text = hill_cipher_decrypt(ciphertext, key_matrix)
print(f"Decrypted  : {decrypted_text}")
