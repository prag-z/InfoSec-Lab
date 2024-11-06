import re

# Function to create the 5x5 matrix for the Playfair cipher
def generate_key_matrix(key):
    key = key.upper().replace('J', 'I')  # 'J' is treated as 'I'
    matrix = []
    seen = set()
    
    # Add the key characters to the matrix
    for char in key:
        if char not in seen and char.isalpha():
            seen.add(char)
            matrix.append(char)
    
    # Add the remaining characters of the alphabet
    for char in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':  # 'J' is omitted
        if char not in seen:
            matrix.append(char)
    
    # Convert list to 5x5 matrix
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

# Function to preprocess the plaintext (remove spaces, adjust digraphs)
def preprocess_text(text):
    text = re.sub(r'[^A-Z]', '', text.upper().replace('J', 'I'))  # Replace 'J' with 'I'
    processed_text = ""
    
    i = 0
    while i < len(text):
        processed_text += text[i]
        if i + 1 < len(text) and text[i] == text[i + 1]:
            processed_text += 'X'  # Insert 'X' if there is a repeated letter
        else:
            i += 1
            if i < len(text):
                processed_text += text[i]
        i += 1
    
    # If there's an odd number of letters, add an extra 'X' at the end
    if len(processed_text) % 2 != 0:
        processed_text += 'X'
    
    return processed_text

# Function to find the position of a letter in the key matrix
def find_position(char, matrix):
    for i, row in enumerate(matrix):
        for j, matrix_char in enumerate(row):
            if matrix_char == char:
                return i, j
    return None

# Function to encrypt a pair of letters using the Playfair cipher
def encrypt_pair(pair, matrix):
    row1, col1 = find_position(pair[0], matrix)
    row2, col2 = find_position(pair[1], matrix)
    
    # Rule 1: If both letters are in the same row, shift right
    if row1 == row2:
        return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
    
    # Rule 2: If both letters are in the same column, shift down
    elif col1 == col2:
        return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
    
    # Rule 3: If the letters form a rectangle, swap columns
    else:
        return matrix[row1][col2] + matrix[row2][col1]

# Function to decrypt a pair of letters using the Playfair cipher
def decrypt_pair(pair, matrix):
    row1, col1 = find_position(pair[0], matrix)
    row2, col2 = find_position(pair[1], matrix)
    
    # Rule 1: If both letters are in the same row, shift left
    if row1 == row2:
        return matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
    
    # Rule 2: If both letters are in the same column, shift up
    elif col1 == col2:
        return matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
    
    # Rule 3: If the letters form a rectangle, swap columns
    else:
        return matrix[row1][col2] + matrix[row2][col1]

# Function to encrypt the plaintext using Playfair cipher
def encrypt(plaintext, key):
    matrix = generate_key_matrix(key)
    plaintext = preprocess_text(plaintext)
    ciphertext = ""
    
    for i in range(0, len(plaintext), 2):
        ciphertext += encrypt_pair(plaintext[i:i+2], matrix)
    
    return ciphertext

# Function to decrypt the ciphertext using Playfair cipher
def decrypt(ciphertext, key):
    matrix = generate_key_matrix(key)
    plaintext = ""
    
    for i in range(0, len(ciphertext), 2):
        plaintext += decrypt_pair(ciphertext[i:i+2], matrix)
    
    return plaintext

# Example usage
plaintext = "Hide the gold in the tree stump"
key = "Playfair Example"

print("Plaintext   : " + plaintext)
print("Key         : " + key)

# Encrypt the plaintext
ciphertext = encrypt(plaintext, key)
print("Ciphertext  : " + ciphertext)

# Decrypt the ciphertext
decrypted_text = decrypt(ciphertext, key)
print("Decrypted   : " + decrypted_text)
