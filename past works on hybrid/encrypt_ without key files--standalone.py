from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def generate_aes_key():
    return get_random_bytes(16)  # 128-bit key for AES-GCM

def symmetric_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return ciphertext, cipher.nonce, tag

def asymmetric_encrypt(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)

def main():
    # Step 1: Symmetric Key Encryption (AES-GCM)
    aes_key = generate_aes_key()
    message = "Hello, this is a secret message!"
    aes_ciphertext, nonce, tag = symmetric_encrypt(message, aes_key)

    # Step 2: Asymmetric Key Encryption (RSA)
    # Replace the following line with code to retrieve your RSA public key from storage
    public_key = RSA.generate(2048).publickey()
    rsa_ciphertext = asymmetric_encrypt(aes_key, public_key)

    # Step 3: Combine Ciphertexts
    combined_ciphertext = aes_ciphertext + rsa_ciphertext

    print("Original Message:", message)
    print("Combined Ciphertext:", combined_ciphertext)

if __name__ == "__main__":
    main()
