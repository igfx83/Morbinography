# %%
import hashlib
import os
import ast
import random
import json
import secrets
import numpy as np
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from PIL import Image

# %%
# Load Morse code dictionary
with open("morse_dict.json", "r") as f:
    morse_code = json.load(f)


class Morbinography:

    def __init__(self, img_path, key_pair=None):
        self.__img_path = img_path
        self.__element_manifest = []
        self.image = None
        self.__seed = None
        self.private_key, self.public_key = self.__initialize_keys(key_pair)
        with open("deck.json", "r") as f:
            self.__deck = json.load(f)

    def __initialize_keys(self, key_pair):
        if key_pair and key_pair[0] and key_pair[1]:
            return key_pair
        private_key, public_key = self.__generate_key_pair()
        return private_key, public_key

    def __generate_key_pair(self):
        try:
            with open("private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None
                )
        except FileNotFoundError:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open("private_key.pem", "wb") as key_file:
                key_file.write(pem)

        public_key = private_key.public_key()
        return private_key, public_key

    def __set_seed(self, seed):
        self.__seed = (self.image.size[0] * self.image.size[1]) % sum(
            [int(c) for c in seed]
        )

    def __encrypt_with_aes(self, data, secret=None):
        secret = secret or self.__get_deck()
        iv = os.urandom(16)
        aes_key = hashlib.sha256("".join(secret).encode()).digest()
        self.__set_seed(aes_key)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_key = self.public_key.encrypt(
            aes_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return iv + encrypted_data, encrypted_key

    def decrypt_with_aes(self, encrypted_data, encrypted_key):
        try:
            aes_key = self.private_key.decrypt(
                bytes(encrypted_key),
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            iv = bytes(encrypted_data[:16])
            self.__set_seed(aes_key)
            encrypted_data = bytes(encrypted_data[16:])
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_padded_data = (
                decryptor.update(encrypted_data) + decryptor.finalize()
            )
            decrypted_data = (
                unpadder.update(decrypted_padded_data) + unpadder.finalize()
            )
            return decrypted_data
        except Exception as e:
            print("Decryption failed:", str(e))
            raise

    def __find_indices(self, keys_1, keys_2):
        return [keys_1.index(key) if key in keys_1 else -1 for key in keys_2]

    def binary_encryption(self, msg):
        original = list(morse_code.keys())
        keys = original.copy()
        secrets.SystemRandom().shuffle(keys)
        codex = self.__find_indices(original, keys)
        encrypted_msg = ""

        for char in msg.upper():
            if char == " ":
                encrypted_msg += "000000"
            elif char in morse_code:
                doo_dahs = morse_code[original[codex[original.index(char)]]]
                for doo in doo_dahs:
                    encrypted_msg += "10" if doo == "." else "1110"
                encrypted_msg += "00"

        # Calculate the length of encrypted_msg
        encrypted_msg_length = len(encrypted_msg)

        # Prepare data for encryption by concatenating encrypted_msg_length with codex bytes
        data_to_encrypt = (
            str(encrypted_msg_length).encode() + b"|" + str(codex).encode()
        )

        # Encrypt the concatenated data
        encrypted_data, encrypted_key = self.__encrypt_with_aes(data_to_encrypt)
        return encrypted_data, encrypted_key, encrypted_msg

    def __get_deck(self):
        secrets.SystemRandom().shuffle(self.__deck)
        return self.__deck

    def get_img(self):
        self.image = Image.open(self.__img_path)
        return self.image

    def __embed_data(self, img, data):
        bits = "".join(format(b, "08b") for b in data[0]) + "".join(
            format(b, "08b") for b in data[1]
        )
        first_byte = format(len(bits), "012b")
        print(bits, len(bits), sep="\n")
        bits = first_byte + bits
        print(first_byte)
        print(bits, len(bits), sep="\n")

        directions = [(1, 0), (0, 1), (-1, 0), (0, -1)]
        x, y, direction_index = 33, 33, 0
        i = 0
        while i < len(bits):
            pixel = list(img.getpixel((x, y)))
            for j in range(3):
                if i >= len(bits):
                    break
                if bits[i] == "1" and pixel[j] % 2 == 0:
                    pixel[j] += 1
                elif bits[i] == "0" and pixel[j] % 2 != 0:
                    pixel[j] -= 1
                i += 1
            self.__element_manifest.append(((x, y), tuple(pixel)))
            img.putpixel((x, y), tuple(pixel))

            dx, dy = directions[direction_index]
            if (
                x + dx < 0
                or x + dx >= img.width
                or y + dy < 0
                or y + dy >= img.height
                or (x + dx, y + dy) in self.__element_manifest
            ):
                direction_index = (direction_index + 1) % 4
                print(direction_index)
            x += directions[direction_index][0]
            y += directions[direction_index][1]
        print(self.__element_manifest)

    def modify_elements(self, image, msg, data):
        if self.__seed is None:
            raise Exception("Seed is Required")
        self.__embed_data(image, data)
        random.seed(self.__seed)

        a = np.asarray(image)
        all_indices = [(i, j) for i in range(a.shape[1]) for j in range(a.shape[0])]
        filtered_indices = [
            idx for idx in all_indices if idx not in self.__element_manifest
        ]
        if len(msg) > len(filtered_indices):
            raise ValueError("Message is too long for the given image.")

        indices = random.sample(filtered_indices, k=len(msg))
        original_indices = indices.copy()

        for j, (x, y) in enumerate(indices):
            pixel = list(image.getpixel((x, y)))
            total = sum(pixel[:3])
            if (total % 2 == 0 and msg[j] == "1") or (total % 2 != 0 and msg[j] == "0"):
                # Adjust all RGB components slightly to minimize visual distortion
                for i in range(3):
                    if pixel[i] < 255:
                        pixel[i] += 1
                    else:
                        pixel[i] -= 1
            image.putpixel((x, y), tuple(pixel))

        return image

    def retrieve_data(self, image):
        directions = [(1, 0), (0, 1), (-1, 0), (0, -1)]
        x, y, direction_index = 33, 33, 0
        bits = ""
        while len(bits) < 12 or len(bits) < int(bits[:12], 2) + 12:
            pixel = image.getpixel((x, y))
            for j in range(3):
                bits += str(pixel[j] % 2)
            self.__element_manifest.append(((x, y), tuple(pixel)))
            dx, dy = directions[direction_index]
            if (
                x + dx < 0
                or x + dx >= image.width
                or y + dy < 0
                or y + dy >= image.height
                or (x + dx, y + dy) in self.__element_manifest
            ):
                direction_index = (direction_index + 1) % 4
            x += directions[direction_index][0]
            y += directions[direction_index][1]

        data_length = int(bits[:12], 2)
        bits = bits[12 : 12 + data_length]
        encoded = []

        num_bytes = len(bits) // 8
        for b in range(num_bytes):  # Adjusted to ensure we only process full bytes
            byte = bits[b * 8 : b * 8 + 8]
            if byte:  # Check if byte is not an empty string
                encoded.append(int(byte, 2))
            else:
                break  # Break the loop if an empty string is encountered

        return encoded[:-256], encoded[-256:]

    def __parse_decrypted_data(self, decrypted_data):
        decoded_str = decrypted_data.decode()
        parts = decoded_str.split("|")
        length = int(parts[0])
        codex = ast.literal_eval(parts[1])
        return length, codex

    def retrieve_elements(self, img, data):
        random.seed(self.__seed)
        length, codex = self.__parse_decrypted_data(data)
        original = list(morse_code.keys())
        reversed_codex = {k: v for k, v in zip(codex, original)}

        a = np.asarray(img)
        all_indices = [(i, j) for i in range(a.shape[1]) for j in range(a.shape[0])]

        filtered_indices = [
            idx for idx in all_indices if idx not in self.__element_manifest
        ]
        indices = random.sample(filtered_indices, k=length)

        msg_bits = ""

        for j, (x, y) in enumerate(indices):
            pixel = list(img.getpixel((x, y)))
            total = sum(pixel[:3])
            if total % 2 == 0:
                msg_bits += "0"
            else:
                msg_bits += "1"

        decrypted_msg = ""
        morse_char = ""
        doo_dahs = list(morse_code.values())
        while len(msg_bits) > 0:
            if msg_bits.startswith("10"):
                morse_char += "."
                msg_bits = msg_bits[2:]
            elif msg_bits.startswith("1110"):
                morse_char += "-"
                msg_bits = msg_bits[4:]
            elif msg_bits.startswith("00"):
                if (
                    morse_char in doo_dahs
                ):  # Check if morse_char is in the values of reversed_codex
                    index = doo_dahs.index(morse_char)
                    decrypted_msg += reversed_codex[index]
                morse_char = ""
                msg_bits = msg_bits[2:]
                if msg_bits.startswith("000000"):
                    decrypted_msg += " "
                    msg_bits = msg_bits[6:]

        return decrypted_msg


# %%
# Example usage:
m = Morbinography("test_1.jpg")
img = m.get_img()

# %%
msg = "Hello, World!"
encrypted_data, encrypted_key, encrypted_msg = m.binary_encryption(msg)

# %%
modified_img = m.modify_elements(
    img.copy(),
    encrypted_msg,
    (encrypted_data, encrypted_key),
)
modified_img.save("modified_image.png")

# %%
# To retrieve data:
m = Morbinography("modified_image.png")
img = m.get_img()
retrieved_data = m.retrieve_data(img.copy())
decrypted_data = m.decrypt_with_aes(*retrieved_data)
decoded_msg = m.retrieve_elements(img.copy(), decrypted_data)
print(decoded_msg)

# %%
