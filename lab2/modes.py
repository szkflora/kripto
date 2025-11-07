def ecb_enc(plaintext, block_size, key, algorithm, IV=None):
    num_blocks = len(plaintext) // block_size
    ciphertext = b""

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = plaintext[start_poz:end_poz]
        encrypted_block = algorithm(block, key)
        ciphertext += encrypted_block

    return ciphertext


def ebc_dec(ciphertext, block_size, key, algorithm, IV=None):
    num_blocks = len(ciphertext) // block_size
    plaintext = b""

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = ciphertext[start_poz:end_poz]
        encrypted_block = algorithm(block, key)
        plaintext += encrypted_block

    return plaintext


def xor_bytes(bytes1, bytes2):
    return bytes([a ^ b for a, b in zip(bytes1, bytes2)])


def cbc_enc(plaintext, block_size, key, algorithm, IV):
    num_blocks = len(plaintext) // block_size
    ciphertext = b""
    previous_encrypted_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = plaintext[start_poz:end_poz]
        encrypted_block_1 = xor_bytes(block, previous_encrypted_block)
        encrypted_block_2 = algorithm(encrypted_block_1, key)
        previous_encrypted_block = encrypted_block_2
        ciphertext += encrypted_block_2

    return ciphertext


def cbc_dec(ciphertext, block_size, key, algorithm, IV):
    num_blocks = len(ciphertext) // block_size
    plaintext = b""
    previous_encrypted_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = ciphertext[start_poz:end_poz]
        decrypted_block_1 = algorithm(block, key)
        decrypted_block_2 = xor_bytes(decrypted_block_1, previous_encrypted_block)
        previous_encrypted_block = block
        plaintext += decrypted_block_2

    return plaintext


def cfb_enc():
    pass


def cfb_dec():
    pass


def ofb_enc():
    pass


def ofb_dec():
    pass


def crt_enc():
    pass


def crt_dec():
    pass
