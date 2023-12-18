from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


def decrypt_aes_gcm(ciphertext_aes, tag, decrypted_aes_key):
    # Assume iv is extracted from the ciphertext (logic not shown here)
    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypted_message = decryptor.update(ciphertext_aes) + decryptor.finalize()
        return decrypted_message
    except cryptography.exceptions.InvalidTag:
        raise ValueError("Authentication tag is invalid.") from None

# Read combined ciphertext
with open('encrypted_message.bin', 'rb') as file:
    combined_ciphertext = file.read()

# Separate RSA ciphertext
rsa_key_length = private_key.key_size // 8
ciphertext_rsa = combined_ciphertext[-rsa_key_length:]

# Extract AES tag and ciphertext
tag = combined_ciphertext[-16:]
ciphertext_aes = combined_ciphertext[:len(combined_ciphertext) - rsa_key_length - 16]

# Decrypt AES key and message
decrypted_aes_key = decrypt_rsa(ciphertext_rsa, private_key)
decrypted_message = decrypt_aes_gcm(ciphertext_aes, tag, decrypted_aes_key)

print("Decryption complete. Decrypted message:")
print(decrypted_message.decode('utf-8'))
