import json
from paddings import pad, zero_pad, des_pad, schneier_ferguson_pad, unpad
from modes import (
    ecb_enc,
    ebc_dec,
    cbc_enc,
    cbc_dec,
    cfb_enc,
    cfb_dec,
    ofb_enc,
    ofb_dec,
    crt_enc,
    crt_dec,
)

FUNCS = {
    "zero_pad": zero_pad,
    "des_pad": des_pad,
    "schneier_ferguson_pad": schneier_ferguson_pad,
    "ebc_enc": ecb_enc,
    "ebc_dec": ebc_dec,
    "cbc_enc": cbc_enc,
    "cbc_dec": cbc_dec,
    "cfb_enc": cfb_enc,
    "cfb_dec": cfb_dec,
    "ofb_enc": ofb_enc,
    "ofb_dec": ofb_dec,
    "crt_enc": crt_enc,
    "crt_dec": crt_dec,
}

config_file_path = "config.json"

file = open(config_file_path, "r")
config_data = json.load(file)

block_size = config_data["block_size"]
key = config_data["key"]
algorithm = config_data["algorithm"]
mode = config_data["mode"]
IV = config_data["IV"]
padding = config_data["padding"]

print(block_size, key, algorithm, mode, IV, padding)

file.close()


def encrypt(plaintext):
    padded_text = pad(plaintext, block_size, FUNCS[padding])
    ciphertext = FUNCS[mode](padded_text, block_size, key, algorithm, IV)
    return ciphertext


def decrypt(ciphertext):
    #### other operations
    #### got padded text from ciphertext
    padded_text = FUNCS[mode](ciphertext, block_size, key, algorithm, IV)
    unpadded_text = unpad(padded_text, padding)
    return unpadded_text
