def pad(text, block_size, func):
    padding_length = block_size - (
        len(text) % block_size
    )  ## padding length is in bytes
    padding = func(padding_length)
    return text + padding


def zero_pad(padding_length):
    return bytes(padding_length)


def des_pad(padding_length):
    return b"\x80" + bytes(padding_length - 1)


def schneier_ferguson_pad(padding_length):
    return bytes([padding_length] * padding_length)


def unpad(padded_text, method, padding_length=None):
    match method:
        case "zero_pad":
            pass  ## and assume padding_length was given as parameter
        case "des_pad":
            padding_length = 1
            i = len(padded_text) - 1
            while padded_text[i] != 0x80:
                i -= 1
                padding_length += 1
                if i == -1:  ## no padding was added to the original text
                    return padded_text
        case "schneier_ferguson_pad":
            padding_length = padded_text[-1]
    return padded_text[:-padding_length]
