from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import messagebox

def generate_keys():
    aes_key = get_random_bytes(32)  # 256 bits for AES
    key = RSA.generate(1024)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return aes_key, private_key, public_key

def get_encryption_input():
    message = input("Enter the message to encrypt: ")
    return message

def get_decryption_input():
    ciphertext = input("Enter the ciphertext to decrypt: ")
    enc_aes_key = input("Enter the encrypted AES key: ")
    nonce = input("Enter the nonce: ")
    tag = input("Enter the tag: ")
    private_key = input("Enter your private key: ")
    return ciphertext, enc_aes_key, nonce, tag, private_key

def hybrid_encrypt(message, aes_key, public_key):
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    cipher_text, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    return cipher_text, enc_aes_key, cipher_aes.nonce, tag

def hybrid_decrypt(cipher_text, enc_aes_key, nonce, tag, private_key):
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    aes_key_ = cipher_rsa.decrypt(enc_aes_key)
    cipher_aes = AES.new(aes_key_, AES.MODE_GCM, nonce=nonce)
    decrypted_message_ = cipher_aes.decrypt_and_verify(cipher_text, tag)
    return decrypted_message_.decode('utf-8')

def encrypt_decrypt():
    operation = input("Do you want to encrypt or decrypt? Enter 'encrypt' or 'decrypt': ")

    if operation.lower() == 'encrypt':
        message = get_encryption_input()
        aes_key, private_key, public_key = generate_keys()
        ciphertext, enc_aes_key, nonce, tag = hybrid_encrypt(message, aes_key, public_key)
        print("\nEncryption Result:")
        print(f"Original Message: {message}")
        print(f"Encrypted AES Key: {enc_aes_key}")
        print(f"Cipher Text: {ciphertext}")
        print(f"Nonce: {nonce}")
        print(f"Tag: {tag}")

    elif operation.lower() == 'decrypt':
        ciphertext, enc_aes_key, nonce, tag, private_key = get_decryption_input()
        decrypted_message = hybrid_decrypt(ciphertext, enc_aes_key, nonce, tag, private_key)
        print("\nDecryption Result:")
        print(f"Decrypted Message: {decrypted_message}")

    else:
        print("Invalid operation. Please enter 'encrypt' or 'decrypt'.")

# Main entry point
if __name__ == "__main__":
    encrypt_decrypt()
