from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# def generate_keys():
#     # Generate AES key
#     aes_key = get_random_bytes(32)  # 256 bits for AES
#
#     # Generate RSA key pair
#     key = RSA.generate(1024)
#     private_key = key.export_key()
#     public_key = key.publickey().export_key()
#
#     return aes_key, private_key, public_key
def generate_keys():
    # Generate RSA key pair
    key = RSA.generate(1024)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key

def hybrid_encrypt(message, aes_key, public_key):
    # Encrypt message with AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

    # Encrypt AES key with RSA
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    return ciphertext, enc_aes_key, cipher_aes.nonce, tag

if __name__ == "__main__":
    # Get input from the user
    message = input("Enter the message to encrypt: ")

    # Generate keys
    aes_key, _, public_key = generate_keys()

    # Encrypt the message
    ciphertext, enc_aes_key, nonce, tag = hybrid_encrypt(message, aes_key, public_key)

    print("\nEncrypted Message:")
    print("Ciphertext:", ciphertext.hex())
    print("Encrypted AES Key:", enc_aes_key.hex())
    print("Nonce:", nonce.hex())
    print("Tag:", tag.hex())
    print("Tag:", _)
