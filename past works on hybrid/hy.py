from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def generate_keys():
    # Generate AES key
    aes_key = get_random_bytes(32)  # 256 bits for AES

    # Generate RSA key pair
    key = RSA.generate(1024)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return aes_key, private_key, public_key


def hybrid_encrypt(message, aes_key, public_key):
    # Encrypt message with AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    print("cipher aes",cipher_aes)
    cipher_text, tag_ = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

    # Encrypt AES key with RSA
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    return cipher_text, enc_aes_key, cipher_aes.nonce, tag_


def hybrid_decrypt(cipher_text, enc_aes_key, nonce, tag, private_key):
    # Decrypt AES key with RSA
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    aes_key_ = cipher_rsa.decrypt(enc_aes_key)

    # Decrypt message with AES-GCM
    cipher_aes = AES.new(aes_key_, AES.MODE_GCM, nonce=nonce)
    decrypted_message_ = cipher_aes.decrypt_and_verify(cipher_text, tag)

    return decrypted_message_.decode('utf-8')


# Example usage:
message = "test message"

# Sender's side
aes_key, private_key, public_key = generate_keys()
ciphertext, enc_aes_key, nonce, tag = hybrid_encrypt(message, aes_key, public_key)

# Receiver's side
decrypted_message = hybrid_decrypt(ciphertext, enc_aes_key, nonce, tag, private_key)

print("Original Message:", message)
print("aes key",enc_aes_key)
print("Cipher Message:", ciphertext)
print("nonce: ",nonce)
print("tag: ",tag)
print("Decrypted Message:", decrypted_message)

print("Private key",private_key)
print("public key ",public_key)
print("aes ",aes_key)
