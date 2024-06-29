# %%
from cryptography.hazmat.primitives import serialization
from morbinography import Morbinography
import os
import json


# %%
class MorbinographyCLI:
    def __init__(self):
        self.morbinography = Morbinography()

    def prompt_for_image(self):
        while True:
            image_path = input("Enter the path to the image: ")
            if os.path.exists(image_path):
                self.morbinography.set_image(image_path)
                break
            else:
                print("Invalid path. Please try again.")

    def run(self):
        os.system("cls" if os.name == "nt" else "clear")
        while True:
            print("1. Encrypt")
            print("2. Decrypt")
            print("3. Exit")
            choice = input("Enter your choice:")
            if choice == "1":
                self.encrypt()
            elif choice == "2":
                self.decrypt()
            elif choice == "3":
                break
            else:
                print("Invalid choice. Please try again.")

    def encrypt(self):
        self.prompt_for_image()
        message = self.prompt_for_message()
        self.prompt_for_recipient(message)

    def decrypt(self):
        self.prompt_for_image()
        retrieved_data = self.morbinography.retrieve_data(self.morbinography.image)
        decrypted_data = self.morbinography.decrypt_with_aes(*retrieved_data)
        decoded_msg = self.morbinography.retrieve_elements(
            self.morbinography.image.copy(), decrypted_data
        )
        print(f"\nDecrypted message: {decoded_msg}\n")

    def prompt_for_message(self):
        while True:
            capacity = self.morbinography.image_capacity
            print(f"Max number of chars: {capacity}")
            message = input("Enter the message to encrypt: ")
            if message:
                if len(message) <= capacity:
                    return message
                else:
                    print("Message too long. Please try again.")
            else:
                print("Invalid message. Please try again.")

    def prompt_for_recipient(self, msg):
        while True:
            recipient_input = input("Enter the recipient's public key or identifier:")
            recipient_key = None

            # Check if the input is a direct key or a dictionary key
            if recipient_input:
                with open("config/contacts.json", "r") as f:
                    public_keys_dict = json.load(f)
                if recipient_input in public_keys_dict:
                    recipient_key = public_keys_dict[recipient_input]
                else:
                    recipient_key = recipient_input

            try:
                encrypted_image = self.morbinography.modify_elements(
                    self.morbinography.image.copy(),
                    *self.morbinography.binary_encryption(msg, recipient_key),
                )
                encrypted_image.save("outputs/modified_image.png")
            except ValueError:
                print("Invalid public key. Please try again.")
                self.prompt_for_recipient(msg)
            print("Success", "\n")

            if recipient_input not in public_keys_dict:
                boolean = input("Would you like to save this public key? (y/n):")
                if boolean.lower() == "y":
                    name = input("Enter the name of the recipient:")
                    contact = recipient_key.replace("\\n", "\n")
                    public_keys_dict[name] = f"b'{contact}'"
                    with open("config/contacts.json", "w") as f:
                        json.dump(public_keys_dict, f)
            return


if __name__ == "__main__":
    cli = MorbinographyCLI()
    cli.run()
