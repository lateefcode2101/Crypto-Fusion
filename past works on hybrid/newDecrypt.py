import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def read_key_from_file(filename, key_type):
    with open(filename, 'rb') as file:
        key_bytes = file.read()
        print(key_bytes)
        print('is the key bytes \n\n')
        if key_type == 'aes':
            return key_bytes
        if key_type == 'rsa_public':
            return serialization.load_pem_public_key(key_bytes, backend=default_backend())
        elif key_type == 'rsa_private':
            return serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())
        else:
            raise ValueError("Invalid key type")


def decrypt_aes_gcm(ciphertext_aes, tag, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypted_message = decryptor.update(ciphertext_aes) + decryptor.finalize()
        return decrypted_message
    except cryptography.exceptions.InvalidTag:
        raise ValueError("Authentication tag is invalid.") from None


def decrypt_combined_ciphertext(filename, private_key):
    # Read the combined ciphertext from the file
    with open(filename, 'rb') as file:
        combined_ciphertext = file.read()

    # Separate RSA ciphertext and GCM tag
    rsa_key_length = private_key.key_size // 8
    print(rsa_key_length)
    print('is the rsa keylength')
    print('size of combined_ciphertext is ' + str(len(combined_ciphertext)))
    ciphertext_rsa = combined_ciphertext[:rsa_key_length]
    print(ciphertext_rsa)
    print('is the ciphertext_rsa and size is ' + str(len(ciphertext_rsa)))
    tag = combined_ciphertext[-16:]
    print(tag)
    print('is the tag')
    ciphertext_aes = combined_ciphertext[rsa_key_length:-16]
    print(ciphertext_aes)
    print('is the ciphertext_aes')

    # Step 1: Decrypt RSA
    try:
        aes_key = private_key.decrypt(ciphertext_rsa, padding.PKCS1v15())
        print("Decrypted RSA key:", aes_key.hex())  # Add this line
    except cryptography.exceptions.InvalidSignature:
        raise ValueError("RSA decryption failed.") from None

    # Step 2: Decrypt AES-GCM
    iv = b'\x00' * 12  # Use the appropriate IV used during encryption
    decrypted_message = decrypt_aes_gcm(ciphertext_aes, tag, aes_key, iv)

    return decrypted_message.decode('utf-8')


# Usage
private_key = read_key_from_file('private_key.pem', 'rsa_private')
print(private_key.key_size)
print(private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8'))
decrypted_message = decrypt_combined_ciphertext('encrypted_message.bin', private_key)
print("Decryption complete. Decrypted message:")
print(decrypted_message)
