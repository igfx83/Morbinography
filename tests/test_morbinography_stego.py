from pathlib import Path

from PIL import Image

from morbinography import Morbinography


def test_encrypt_decrypt_round_trip(tmp_path):
    img_path = tmp_path / "sample.png"
    Image.new("RGB", (200, 200), color=(255, 255, 255)).save(img_path)

    sender = Morbinography(img_path=str(img_path))
    sender.set_image(str(img_path))
    msg = "hello world"
    recipient_key = sender.public_key_pem()

    encrypted_msg, data = sender.binary_encryption(msg, recipient_key)
    encrypted_image = sender.modify_elements(sender.image.copy(), encrypted_msg, data)

    out_path = tmp_path / "encrypted.png"
    encrypted_image.save(out_path)

    receiver = Morbinography()
    receiver.set_image(str(out_path))
    recovered_data = receiver.retrieve_data(receiver.image)
    decrypted_bytes = receiver.decrypt_with_aes(*recovered_data)
    recovered_msg = receiver.retrieve_elements(receiver.image.copy(), decrypted_bytes)

    assert recovered_msg == msg
