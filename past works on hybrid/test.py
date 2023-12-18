from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import messagebox
import os
import time
import cProfile
import logging

PRIVATE_KEY_FILE = "private_key.pem"

# Set up logging
logging.basicConfig(level=logging.INFO)

def generate_keys():
    aes_key = get_random_bytes(32)  # 256 bits for AES
    key = RSA.generate(1024)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return aes_key, private_key, public_key

def save_private_key(private_key):
    with open(PRIVATE_KEY_FILE, "wb") as file:
        file.write(private_key)

def load_private_key():
    if os.path.exists(PRIVATE_KEY_FILE):
        with open(PRIVATE_KEY_FILE, "rb") as file:
            private_key = file.read()
        return private_key
    else:
        return None

def get_encryption_input():
    message = input("Enter the message to encrypt: ")
    return message

def get_decryption_input():
    # Use hex format for easier input
    ciphertext = bytes.fromhex(input("Enter the ciphertext to decrypt (in hex format): "))
    enc_aes_key = bytes.fromhex(input("Enter the encrypted AES key (in hex format): "))
    nonce = bytes.fromhex(input("Enter the nonce (in hex format): "))
    tag = bytes.fromhex(input("Enter the tag (in hex format): "))
    private_key = load_private_key()

    # Print inputs for debugging
    logging.info(f"Ciphertext: {ciphertext}")
    logging.info(f"Encrypted AES Key: {enc_aes_key}")
    logging.info(f"Nonce: {nonce}")
    logging.info(f"Tag: {tag}")
    logging.info(f"Private Key: {private_key}")

    return ciphertext, enc_aes_key, nonce, tag, private_key

def hybrid_encrypt(message, aes_key, public_key):
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    cipher_text, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    private_key = generate_keys()[1]  # Retrieve private key from generate_keys
    save_private_key(private_key)
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

        # Profiling
        with cProfile.Profile() as pr:
            start_time = time.time()
            ciphertext, enc_aes_key, nonce, tag = hybrid_encrypt(message, aes_key, public_key)
            end_time = time.time()
            execution_time = end_time - start_time
            print("\nEncryption Result:")
            print(f"Original Message: {message}")
            print(f"Encrypted AES Key: {enc_aes_key}")
            print(f"Cipher Text: {ciphertext}")
            print(f"Nonce: {nonce}")
            print(f"Tag: {tag}")
            print(f"Execution Time: {execution_time} seconds")

        # Print profiling results
        pr.print_stats()

    elif operation.lower() == 'decrypt':
        # Profiling
        with cProfile.Profile() as pr:
            start_time = time.time()
            ciphertext, enc_aes_key, nonce, tag, private_key = get_decryption_input()
            decrypted_message = hybrid_decrypt(ciphertext, enc_aes_key, nonce, tag, private_key)
            end_time = time.time()
            execution_time = end_time - start_time
            print("\nDecryption Result:")
            print(f"Decrypted Message: {decrypted_message}")
            print(f"Execution Time: {execution_time} seconds")

        # Print profiling results
        pr.print_stats()

    else:
        print("Invalid operation. Please enter 'encrypt' or 'decrypt'.")

# Main entry point
if __name__ == "__main__":
    encrypt_decrypt()
