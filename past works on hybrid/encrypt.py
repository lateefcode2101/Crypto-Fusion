from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def read_key_from_file(filename, key_type):
    with open(filename, 'rb') as file:
        key_bytes = file.read()
        if key_type == 'aes':
            return key_bytes
        elif key_type == 'rsa_public':
            return serialization.load_pem_public_key(key_bytes, backend=default_backend())
        elif key_type == 'rsa_private':
            return serialization.load_pem_private_key(key_bytes, password=b'abrar', backend=default_backend())
        else:
            raise ValueError("Invalid key type")


def encrypt_aes_gcm(message, aes_key):
    iv = b'\x00' * 12  # Initialization vector (IV) for GCM
    aes_key = aes_key[:32]  # Ensure the key is 32 bytes (256 bits)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, tag


def encrypt_rsa(data, public_key):
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# Read keys from files
aes_key = read_key_from_file('aes-256-key.txt', 'aes')
print("AES Key is read from file as it is")
print(aes_key)
public_key = read_key_from_file('public_key.pem', 'rsa_public')

# Get message from user
message = input("Enter the message to encrypt: ").encode('utf-8')

# Step 2.1: Symmetric Key Encryption (AES-GCM)
ciphertext_aes, tag = encrypt_aes_gcm(message, aes_key)
print(f"Tag length: {len(tag)}")
print("Encryption complete.")

# Step 2.2: Asymmetric Key Encryption (RSA)
ciphertext_rsa = encrypt_rsa(aes_key, public_key)

# Step 2.3: Combine Ciphertexts
combined_ciphertext = ciphertext_aes + tag + ciphertext_rsa

# Store the combined ciphertext in a file
with open('encrypted_message.bin', 'wb') as file:
    file.write(combined_ciphertext)

print("Combined ciphertext stored in 'encrypted_message.bin'.")
