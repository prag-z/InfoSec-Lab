import hashlib

#DJB2 Hash Function - Lab 5: Q1, Q2
def djb2(inputString):
    hashValue = 5381

    for char in inputString:
        hashValue = ((hashValue*33) + ord(char)) &0xFFFFFFFF
    
    return hashValue

hashy = [2272792705]

#Verifying inputted string with pre-stored hash value
password = str(input("Enter Password: "))
if (djb2(password) == hashy[0]):
    print("Password Entered Correctly")
else:
    print(f"Incorrect Password, Try Again\nHash Value: {djb2(password)}")

#Implementing SHA-1, MD-5, SHA-256
def hashFunctions(input_string):

    #md5 hashing
    md5_hash = hashlib.md5(input_string.encode()).hexdigest()

    #sha1 hashing
    sha1_hash = hashlib.sha1(input_string.encode()).hexdigest()

    #sha256 hashing
    sha256_hash = hashlib.sha256(input_string.encode()).hexdigest()

    #sha512 hashing
    sha512_hash = hashlib.sha512(input_string.encode()).hexdigest()

    return [md5_hash, sha1_hash, sha256_hash, sha512_hash]

def whirlpool_hash(input_string):
    """Computes the Whirlpool hash of the input string."""
    # Create a new Whirlpool hash object
    hasher = hashlib.new('whirlpool')
    # Update the hasher with the input data
    hasher.update(input_string.encode())
    # Return the hexadecimal digest of the hash
    return hasher.hexdigest()

hashes = []
hashes = hashFunctions("Hello World")
for element in hashes:
    print(element)

print("Whirlpool Hash: ", whirlpool_hash("Hello World"))

