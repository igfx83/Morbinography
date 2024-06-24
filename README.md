# Morbinography

Morbinography is a Python library for secure image-based data encryption and decryption. It leverages advanced cryptographic techniques, including AES and RSA algorithms, to embed encrypted messages within images. This library is designed for applications requiring secure data transmission and storage with an additional layer of steganography for enhanced security.

## Features

- **Image Encryption**: Embeds encrypted data within images using a combination of AES and RSA encryption algorithms.
- **Data Steganography**: Utilizes steganographic techniques to hide encrypted data within the pixel values of images, making the presence of the encrypted data undetectable.
- **Secure Key Management**: Generates and manages RSA key pairs for encryption and decryption, with support for custom key pairs.
- **Morse Code Encryption**: Offers an additional layer of encryption by converting messages into Morse code before binary encryption.
- **Dynamic Seed Generation**: Uses image properties to generate a dynamic seed for encryption, ensuring unique encryption patterns for each image.

## Installation

To use Morbinography, clone this repository and ensure you have the required dependencies installed:

```bash
git clone https://github.com/yourusername/morbinography.git
cd morbinography
pip install -r requirements.txt
```
# Usage
## Initializing Morbinography
```python
from morbinography import Morbinography
```
## Initialize with an image path and optionally a key pair
```python
morbinography = Morbinography(img_path="path/to/image.png")
```
# Encrypting Data

## Encrypt a message
```python
encrypted_data, encrypted_key, encrypted_msg = morbinography.binary_encryption("Hello World")
```
## Embed the encrypted data into an image
```python
image = morbinography.get_img()
morbinography.modify_elements(image, encrypted_msg, (encrypted_data, encrypted_key))
image.save("encrypted_image.png")
```
# Decrypting Data

## Load the encrypted image
encrypted_image = Image.open("encrypted_image.png")

## Retrieve encrypted data from the image
encrypted_data, encrypted_key = morbinography.retrieve_data(encrypted_image)

## Decrypt the data
decrypted_data = morbinography.decrypt_with_aes(encrypted_data, encrypted_key)

## Parse the decrypted data to get the original message length and codex
length, codex = morbinography.__parse_decrypted_data(decrypted_data)

Dependencies
Pillow for image processing.
Cryptography for encryption and decryption.
Numpy for array manipulation.
Contributing
Contributions are welcome! Please feel free to submit a pull request.

License
This project is licensed under the MIT License - see the LICENSE file for details. 
