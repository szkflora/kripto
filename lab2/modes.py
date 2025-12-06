import numpy as np


def ecb_enc(plaintext, block_size, key, algorithm, IV=None):
    num_blocks = len(plaintext) // block_size
    ciphertext = bytearray(len(plaintext))

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = plaintext[start_poz:end_poz]
        encrypted_block = algorithm(block, key)
        ciphertext[start_poz:end_poz] = encrypted_block

    return bytes(ciphertext)


def ecb_dec(ciphertext, block_size, key, algorithm, IV=None):
    return ecb_enc(ciphertext, block_size, key, algorithm, IV)


def xor_bytes(bytes1, bytes2):
    return np.bitwise_xor(
        np.frombuffer(bytes1, dtype=np.uint8), np.frombuffer(bytes2, dtype=np.uint8)
    ).tobytes()


def complement_bytes(IV, n):
    IV_len = len(IV)
    if IV_len < n:
        padding_needed = n - IV_len
        zero_padding = b"\x00" * padding_needed
        return zero_padding + IV
    elif IV_len > n:
        return IV[IV_len - n :]
    else:
        return IV


def increment_counter(counter):
    counter_int = int.from_bytes(counter, "big")
    counter_int += 1
    new_counter = counter_int.to_bytes(len(counter), "big")
    return new_counter


def cbc_enc(plaintext, block_size, key, algorithm, IV):
    num_blocks = len(plaintext) // block_size
    ciphertext = bytearray(len(plaintext))
    previous_encrypted_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = plaintext[start_poz:end_poz]
        encrypted_block_1 = xor_bytes(block, previous_encrypted_block)
        encrypted_block_2 = algorithm(encrypted_block_1, key)
        previous_encrypted_block = encrypted_block_2
        ciphertext[start_poz:end_poz] = encrypted_block_2

    return bytes(ciphertext)


def cbc_dec(ciphertext, block_size, key, algorithm, IV):
    num_blocks = len(ciphertext) // block_size
    plaintext = bytearray(len(ciphertext))
    previous_encrypted_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = ciphertext[start_poz:end_poz]
        decrypted_block_1 = algorithm(block, key)
        decrypted_block_2 = xor_bytes(decrypted_block_1, previous_encrypted_block)
        previous_encrypted_block = block
        plaintext[start_poz:end_poz] = decrypted_block_2

    return bytes(plaintext)


def cfb_enc(plaintext, block_size, key, algorithm, IV):
    num_blocks = len(plaintext) // block_size
    ciphertext = bytearray(len(plaintext))
    previous_encrypted_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = plaintext[start_poz:end_poz]
        encrypted_block_1 = algorithm(previous_encrypted_block, key)
        encrypted_block_2 = xor_bytes(encrypted_block_1, block)
        previous_encrypted_block = encrypted_block_2
        ciphertext[start_poz:end_poz] = encrypted_block_2

    return bytes(ciphertext)


def cfb_dec(ciphertext, block_size, key, algorithm, IV):
    num_blocks = len(ciphertext) // block_size
    plaintext = bytearray(len(ciphertext))
    previous_encrypted_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = ciphertext[start_poz:end_poz]
        decrypted_block_1 = algorithm(previous_encrypted_block, key)
        decrypted_block_2 = xor_bytes(decrypted_block_1, block)
        previous_encrypted_block = block
        plaintext[start_poz:end_poz] = decrypted_block_2

    return bytes(plaintext)


def ofb_enc(plaintext, block_size, key, algorithm, IV):
    num_blocks = len(plaintext) // block_size
    ciphertext = bytearray(len(plaintext))
    previous_helper_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = plaintext[start_poz:end_poz]
        helper_block = algorithm(previous_helper_block, key)
        encrypted_block = xor_bytes(block, helper_block)
        previous_helper_block = helper_block
        ciphertext[start_poz:end_poz] = encrypted_block

    return bytes(ciphertext)


def ofb_dec(ciphertext, block_size, key, algorithm, IV):
    return ofb_enc(ciphertext, block_size, key, algorithm, IV)


def ctr_enc(plaintext, block_size, key, algorithm, IV):
    num_blocks = len(plaintext) // block_size
    ciphertext = bytearray(len(plaintext))
    counter = complement_bytes(IV, block_size)

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = plaintext[start_poz:end_poz]
        helper_block = algorithm(counter, key)
        encrypted_block = xor_bytes(block, helper_block)
        counter = increment_counter(counter)
        ciphertext[start_poz:end_poz] = encrypted_block

    return bytes(ciphertext)


def ctr_dec(ciphertext, block_size, key, algorithm, IV):
    return ctr_enc(ciphertext, block_size, key, algorithm, IV)
