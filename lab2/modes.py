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


def ecb_dec(ciphertext, block_size, key, algorithm, IV=None):
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


def cfb_enc(plaintext, block_size, key, algorithm, IV):
    num_blocks = len(plaintext) // block_size
    ciphertext = b""
    previous_encrypted_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = plaintext[start_poz:end_poz]
        encrypted_block_1 = algorithm(previous_encrypted_block, key)
        encrypted_block_2 = xor_bytes(encrypted_block_1, block)
        previous_encrypted_block = encrypted_block_2
        ciphertext += encrypted_block_2

    return ciphertext


def cfb_dec(ciphertext, block_size, key, algorithm, IV):
    num_blocks = len(ciphertext) // block_size
    plaintext = b""
    previous_encrypted_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = ciphertext[start_poz:end_poz]
        decrypted_block_1 = algorithm(previous_encrypted_block, key)
        decrypted_block_2 = xor_bytes(decrypted_block_1, block)
        previous_encrypted_block = block
        plaintext += decrypted_block_2

    return plaintext


def ofb_enc(plaintext, block_size, key, algorithm, IV):
    num_blocks = len(plaintext) // block_size
    ciphertext = b""
    previous_helper_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = plaintext[start_poz:end_poz]
        helper_block = algorithm(previous_helper_block, key)
        encrypted_block = xor_bytes(block, helper_block)
        previous_helper_block = helper_block
        ciphertext += encrypted_block

    return ciphertext


def ofb_dec(ciphertext, block_size, key, algorithm, IV):
    num_blocks = len(ciphertext) // block_size
    plaintext = b""
    previous_helper_block = IV

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = ciphertext[start_poz:end_poz]
        helper_block = algorithm(previous_helper_block, key)
        decrypted_block = xor_bytes(block, helper_block)
        previous_helper_block = helper_block
        plaintext += decrypted_block

    return plaintext


def ctr_enc(plaintext, block_size, key, algorithm, IV):
    num_blocks = len(plaintext) // block_size
    ciphertext = b""
    counter = complement_bytes(IV, block_size)

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = plaintext[start_poz:end_poz]
        helper_block = algorithm(counter, key)
        encrypted_block = xor_bytes(block, helper_block)
        counter = increment_counter(counter)
        ciphertext += encrypted_block

    return ciphertext


def ctr_dec(ciphertext, block_size, key, algorithm, IV):
    num_blocks = len(ciphertext) // block_size
    plaintext = b""
    counter = complement_bytes(IV, block_size)

    for i in range(num_blocks):
        start_poz = i * block_size
        end_poz = start_poz + block_size
        block = ciphertext[start_poz:end_poz]
        helper_block = algorithm(counter, key)
        decrypted_block = xor_bytes(block, helper_block)
        counter = increment_counter(counter)
        plaintext += decrypted_block

    return plaintext


ctr_enc(
    b"\x00\x00\x00\x00\x00\x00\x00\x00",
    8,
    b"\x00\x00\x00\x00\x00\x00\x00\x00",
    xor_bytes,
    b"\x00\x00\x00\x00\x00\x00\x00\x00",
)
