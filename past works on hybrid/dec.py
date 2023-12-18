from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def hybrid_decrypt(ciphertext, enc_aes_key, nonce, tag, private_key):
    # Decrypt AES key with RSA
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    # Decrypt message with AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_message.decode('utf-8')

if __name__ == "__main__":
    # Get input from the user
    ciphertext = bytes.fromhex(input("Enter the ciphertext: "))
    enc_aes_key = bytes.fromhex(input("Enter the encrypted AES key: "))
    nonce = bytes.fromhex(input("Enter the nonce: "))
    tag = bytes.fromhex(input("Enter the tag: "))
    private_key = input("Enter your private key: ")

    # Decrypt the message
    decrypted_message = hybrid_decrypt(ciphertext, enc_aes_key, nonce, tag, private_key)

    print("\nDecrypted Message:")
    print(decrypted_message)
