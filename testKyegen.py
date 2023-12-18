from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Replace 'your_hex_key_here' with the actual hex key you generated
aes_key_hex = '6fee52a2987a08e4ae5542eea5c84d6682052159da2b7cb8f7d7d8be2422387a'
aes_key = bytes.fromhex(aes_key_hex)
print(aes_key)

# Assuming 'iv' is your initialization vector (16 bytes for GCM mode)
iv = b'\x00' * 16

# Create a cipher object
cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())

# Create an encryptor or decryptor as needed
encryptor = cipher.encryptor()

print(encryptor)
# Use the encryptor to encrypt your data

# Note: Make sure to handle the key and IV securely and in a way that suits your application.
