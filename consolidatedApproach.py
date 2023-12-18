import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def read_key_from_file(filename, key_type):
    with open(filename, 'rb') as file:
        key_bytes = file.read().strip()
        if key_type == 'aes':
            return key_bytes
        elif key_type == 'rsa_private':
            return serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())
        elif key_type == 'rsa_public':
            return serialization.load_pem_public_key(key_bytes, backend=default_backend())
        else:
            raise ValueError("Invalid key type")

def encrypt_aes_gcm(message, aes_key):
    iv = b'\x00' * 12  # Initialization vector (IV) for GCM
    aes_key = aes_key[:32]  # Ensure the key is 32 bytes (256 bits)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, tag, iv

def encrypt_rsa(aes_key, public_key):
    # Ensure the AES key is padded to the correct size
    aes_key = aes_key.ljust(32, b'\0')[:32]

    ciphertext_rsa = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext_rsa

def decrypt_aes_gcm(ciphertext_aes, tag, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext_aes) + decryptor.finalize()
    return decrypted_message


def decrypt_rsa(ciphertext_rsa, private_key):
    decrypted_aes_key = private_key.decrypt(
        ciphertext_rsa,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Ensure the decrypted AES key has a valid size (32 bytes for AES-256)
    if len(decrypted_aes_key) != 32:
        raise ValueError("Decrypted AES key has invalid size.")

    return decrypted_aes_key


# File paths for AES and RSA keys
aes_key_file = 'aes-256-key.txt'
rsa_private_key_file = 'private_key.pem'
rsa_public_key_file = 'public_key.pem'

# Read AES key from file
aes_key = read_key_from_file(aes_key_file, 'aes')

# Read RSA private key from file
private_key = read_key_from_file(rsa_private_key_file, 'rsa_private')

# Read RSA public key from file (if needed)
# public_key = read_key_from_file(rsa_public_key_file, 'rsa_public')

# Original message to be encrypted
original_message = b"This is a secret message."

# Encrypt the message
ciphertext_aes, tag, iv = encrypt_aes_gcm(original_message, aes_key)
ciphertext_rsa = encrypt_rsa(aes_key, private_key.public_key())

# Combine the ciphertexts for storage or transmission
combined_ciphertext = ciphertext_aes + tag + ciphertext_rsa
print(combined_ciphertext)
# Save the combined ciphertext to a file
with open('encrypted_message.bin', 'wb') as file:
    file.write(combined_ciphertext)

# Read the combined ciphertext from the file
with open('encrypted_message.bin', 'rb') as file:
    combined_ciphertext = file.read()

# Separate AES-GCM ciphertext, tag, and RSA ciphertext
rsa_key_length = private_key.key_size // 8
ciphertext_aes = combined_ciphertext[:len(combined_ciphertext) - rsa_key_length - 16]
tag = combined_ciphertext[len(combined_ciphertext) - rsa_key_length - 16: len(combined_ciphertext) - rsa_key_length]
ciphertext_rsa = combined_ciphertext[len(combined_ciphertext) - rsa_key_length:]

# Decrypt the AES key using RSA private key
decrypted_aes_key = decrypt_rsa(ciphertext_rsa, private_key)

# Decrypt the original message using the AES key
decrypted_message = decrypt_aes_gcm(ciphertext_aes, tag, decrypted_aes_key, iv)

print("Decryption complete. Decrypted message:")
print(decrypted_message.decode('utf-8'))
