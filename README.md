# CryptoFusion

CryptoFusion is a Python implementation of a hybrid encryption and decryption system using both AES and RSA algorithms. This provides a secure and efficient way to protect your sensitive data.

## Features

- **Hybrid Encryption:** Utilizes a combination of AES-GCM and RSA to achieve a hybrid encryption scheme, benefiting from the strengths of both symmetric and asymmetric encryption.
- **Password-Protected Private Key:** Enhances security by allowing the use of a password-protected RSA private key for decryption.
- **Dynamic Message Input:** Provides flexibility by allowing the user to input the message interactively or load it from a text file.
- **Graceful Password Handling:** Allows multiple password attempts for the private key with a user-friendly prompt.

## Getting Started

### Prerequisites

- Python 3.x
- Install required dependencies: `pip install cryptography`

### Usage

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/lateefcode2101/hybrid-encryption.git
   cd hybrid-encryption
   ```

2. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Encryption and Decryption:**

   - Execute `consolidatedApproach.py` to run the hybrid encryption and decryption process.

4. **Follow the Interactive Prompts:**

   - The system will guide you through entering the necessary information, such as the message and password.

5. **Review the Output:**

   - The encrypted message will be stored in `encrypted_message.bin`, and the decrypted message will be displayed.

## File Structure

- `consolidatedApproach.py`: Main script containing the hybrid encryption and decryption implementation.
- `aes-256-key.txt`: File containing the AES-256 key.
- `private_key.pem`: Password-protected RSA private key.
- `public_key.pem`: Corresponding RSA public key.
- `message.txt`: Text file containing the original message.

## Contributing

Contributions are welcome! Feel free to open issues or pull requests for improvements or additional features.