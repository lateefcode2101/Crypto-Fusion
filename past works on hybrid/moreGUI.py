from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import messagebox

class HybridEncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Hybrid Encryption/Decryption")

        self.message_label = tk.Label(master, text="Enter Message:")
        self.message_entry = tk.Entry(master, width=30)

        self.generate_keys_button = tk.Button(master, text="Generate Keys", command=self.generate_keys)
        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)

        self.result_text = tk.Text(master, height=10, width=40, state=tk.DISABLED)

        self.aes_key = None
        self.private_key = None
        self.public_key = None
        self.ciphertext = None
        self.enc_aes_key = None
        self.nonce = None
        self.tag = None
        self.decrypted_message = None

        self.message_label.grid(row=0, column=0, pady=5)
        self.message_entry.grid(row=0, column=1, pady=5)

        self.generate_keys_button.grid(row=1, column=0, columnspan=2, pady=10)
        self.encrypt_button.grid(row=2, column=0, pady=5)
        self.decrypt_button.grid(row=2, column=1, pady=5)

        self.result_text.grid(row=3, column=0, columnspan=2, pady=10)

    def generate_keys(self):
        self.aes_key, self.private_key, self.public_key = generate_keys()
        messagebox.showinfo("Key Generation", "Keys generated successfully!")

    def encrypt(self):
        if not self.aes_key or not self.public_key:
            messagebox.showerror("Error", "Generate keys first!")
            return

        message = self.message_entry.get()
        if not message:
            messagebox.showerror("Error", "Enter a message!")
            return

        self.ciphertext, self.enc_aes_key, self.nonce, self.tag = hybrid_encrypt(message, self.aes_key, self.public_key)

        result_text = f"Original Message: {message}\n" \
                      f"Encrypted AES Key: {self.enc_aes_key}\n" \
                      f"Cipher Text: {self.ciphertext}\n" \
                      f"Nonce: {self.nonce}\n" \
                      f"Tag: {self.tag}\n"

        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result_text)
        self.result_text.config(state=tk.DISABLED)

    def decrypt(self):
        if not self.private_key:
            messagebox.showerror("Error", "Generate keys first!")
            return

        if not self.ciphertext or not self.enc_aes_key or not self.nonce or not self.tag:
            messagebox.showerror("Error", "Encrypt a message first!")
            return

        self.decrypted_message = hybrid_decrypt(self.ciphertext, self.enc_aes_key, self.nonce, self.tag, self.private_key)

        result_text = f"Decrypted Message: {self.decrypted_message}"

        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result_text)
        self.result_text.config(state=tk.DISABLED)


def generate_keys():
    aes_key = get_random_bytes(32)
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


if __name__ == "__main__":
    root = tk.Tk()
    app = HybridEncryptionApp(root)
    root.mainloop()
