import json
import base64
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
    aes_enc,
    aes_dec,
    my_enc,
    my_dec,
)

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
        ciphertext, cgf["block_size"], cgf["key"], FUNCS[cgf["algorithm"]], cgf["IV"]
    )
    unpadded_text = unpad(padded_text, cgf["padding"])
    return unpadded_text
