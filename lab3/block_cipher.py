import json
import base64
import numpy as np
from Crypto.Cipher import AES
from paddings import pad, zero_pad, des_pad, schneier_ferguson_pad, unpad
from modes import (
    ecb_enc,
    ecb_dec,
    cbc_enc,
    cbc_dec,
    cfb_enc,
    cfb_dec,
    ofb_enc,
    ofb_dec,
    ctr_enc,
    ctr_dec,
)


def my_enc(data, key):

    data_array = np.frombuffer(data, dtype=np.uint8)
    key_array = np.frombuffer(key, dtype=np.uint8)
    data_len = len(data_array)
    key_len = len(key_array)
    shift_amount = key_len % data_len
    shifted_data = np.roll(data_array, shift_amount)
    key_stream = np.tile(key_array, data_len // key_len + 1)[:data_len]
    ciphertext_array = np.bitwise_xor(shifted_data, key_stream)

    return ciphertext_array.tobytes()


def my_dec(ciphertext, key):
    if not ciphertext:
        return b""
    ciphertext_array = np.frombuffer(ciphertext, dtype=np.uint8)
    key_array = np.frombuffer(key, dtype=np.uint8)
    data_len = len(ciphertext_array)
    key_len = len(key_array)
    shift_amount = key_len % data_len
    key_stream = np.tile(key_array, data_len // key_len + 1)[:data_len]
    xored_data = np.bitwise_xor(ciphertext_array, key_stream)
    decrypted_array = np.roll(xored_data, -shift_amount)

    return decrypted_array.tobytes()


def aes_enc(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)


def aes_dec(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)


FUNCS = {
    "zero_pad": zero_pad,
    "des_pad": des_pad,
    "schneier_ferguson_pad": schneier_ferguson_pad,
    "ecb_enc": ecb_enc,
    "ecb_dec": ecb_dec,
    "cbc_enc": cbc_enc,
    "cbc_dec": cbc_dec,
    "cfb_enc": cfb_enc,
    "cfb_dec": cfb_dec,
    "ofb_enc": ofb_enc,
    "ofb_dec": ofb_dec,
    "ctr_enc": ctr_enc,
    "ctr_dec": ctr_dec,
    "aes_enc": aes_enc,
    "aes_dec": aes_dec,
    "my_enc": my_enc,
    "my_dec": my_dec,
}


def load_config():
    config_file_path = "config.json"
    file = open(config_file_path, "r")
    cgf = json.load(file)
    cgf["key"] = base64.b64decode(cgf["key"])
    cgf["IV"] = base64.b64decode(cgf["IV"])
    file.close()
    return cgf


def encrypt(plaintext):
    cgf = load_config()
    padded_text = pad(plaintext, cgf["block_size"], FUNCS[cgf["padding"]])
    ciphertext = FUNCS[cgf["mode"]](
        padded_text, cgf["block_size"], cgf["key"], FUNCS[cgf["algorithm"]], cgf["IV"]
    )
    return ciphertext


def decrypt(ciphertext):
    cgf = load_config()
    padded_text = FUNCS[cgf["mode"]](
        ciphertext, cgf["block_size"], cgf["key"], FUNCS[cgf["dalgorithm"]], cgf["IV"]
    )
    unpadded_text = unpad(padded_text, cgf["padding"])
    return unpadded_text
