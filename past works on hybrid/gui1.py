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
    message = entry_message.get()

    aes_key, private_key, public_key = generate_keys()
    ciphertext, enc_aes_key, nonce, tag = hybrid_encrypt(message, aes_key, public_key)
    decrypted_message = hybrid_decrypt(ciphertext, enc_aes_key, nonce, tag, private_key)

    # Displaying the results in labels for easy copying
    label_original_message.config(text=f"Original Message: {message}")
    label_encrypted_aes_key.config(text=f"Encrypted AES Key: {enc_aes_key}")
    label_cipher_text.config(text=f"Cipher Text: {ciphertext}")
    label_nonce.config(text=f"Nonce: {nonce}")
    label_tag.config(text=f"Tag: {tag}")
    label_decrypted_message.config(text=f"Decrypted Message: {decrypted_message}")

# Create the main window
window = tk.Tk()
window.title("Hybrid Encryption/Decryption")

# Create UI components
label_message = tk.Label(window, text="Enter Message:")
entry_message = tk.Entry(window, width=30)
button_encrypt_decrypt = tk.Button(window, text="Encrypt/Decrypt", command=encrypt_decrypt)

# Labels to display dynamic content
label_original_message = tk.Label(window, text="")
label_encrypted_aes_key = tk.Label(window, text="")
label_cipher_text = tk.Label(window, text="")
label_nonce = tk.Label(window, text="")
label_tag = tk.Label(window, text="")
label_decrypted_message = tk.Label(window, text="")

# Place UI components on the window
label_message.pack(pady=5)
entry_message.pack(pady=5)
button_encrypt_decrypt.pack(pady=10)
label_original_message.pack(pady=5)
label_encrypted_aes_key.pack(pady=5)
label_cipher_text.pack(pady=5)
label_nonce.pack(pady=5)
label_tag.pack(pady=5)
label_decrypted_message.pack(pady=5)

# Start the GUI event loop
window.mainloop()
