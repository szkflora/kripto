import json
from io import BytesIO
from PIL import Image
from block_cipher import encrypt, decrypt

config_data = {
    "block_size": 16,
    "key": "U2l4dGVlbiBieXRlIGtleQ==",
    "IV": "AAAAAAAAAAAAAAAAAAAAAA==",
    "algorithm": "aes_enc",
    "mode": "ecb_enc",
    "padding": "schneier_ferguson_pad",
}

config_file_path = "config.json"


with open(config_file_path, "w") as f:
    json.dump(config_data, f, indent=2)


#################

img = Image.open("kep.jpg")
buffer = BytesIO()
img.save(buffer, format="PNG")
img_bytes = buffer.getvalue()

#################

ciphertext = encrypt(img_bytes)

config_data["algorithm"] = "aes_dec"
config_data["mode"] = "ecb_dec"
with open(config_file_path, "w") as f:
    json.dump(config_data, f, indent=2)

decrypted_bytes = decrypt(ciphertext)


def test():
    assert decrypted_bytes == img_bytes
