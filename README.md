# Morbinography

Morbinography is a Python library for secure image-based data encryption and decryption. It leverages advanced cryptographic techniques, including AES and RSA algorithms, to embed encrypted messages within images. This library is designed for applications requiring secure data transmission and storage with an additional layer of steganography for enhanced security.

## Features

- **Image Encryption**: Embeds encrypted data within images using a combination of AES and RSA encryption algorithms.
- **Data Steganography**: Utilizes steganographic techniques to hide encrypted data within the pixel values of images, making the presence of the encrypted data undetectable.
- **Secure Key Management**: Generates and manages RSA key pairs for encryption and decryption, with support for custom key pairs.
- **Morse Code Encryption**: Offers an additional layer of encryption by converting messages into Morse code before binary encryption.
- **Dynamic Seed Generation**: Uses image properties to generate a dynamic seed for encryption, ensuring unique encryption patterns for each image.

License
This project is licensed under the MIT License - see the LICENSE file for details. 
