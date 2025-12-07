import base64
import json
import os
from socket import *
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from block_cipher import decrypt, encrypt, load_config

SERVER_NAME = "localhost"
CLIENT_NAME = "localhost"
SERVER_PORT = 12000
OWN_ID = None
RUNNING = True
OTHER_CLIENT_ID = None
OWN_PUB_KEY = None
OWN_PRIV_KEY = None
THEIR_PUBLIC_KEY = None
SUPPORTED_MODES = ["ecb_enc", "cbc_enc", "cfb_enc", "ofb_enc", "ctr_enc"]
SUPPORTED_ALGOS = ["aes_enc", "my_enc"]
SUPPORTED_DALGOS = ["aes_dec", "my_dec"]
SUPPORTED_PADDINGS = ["schneier_ferguson_pad"]
OWN_HALF_SECRET = None
THEIR_HALF_SECRET = None


def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return public_pem.decode(), private_pem.decode()


def rsa_encrypt(data: bytes, pem_public_key: str):
    public_key = serialization.load_pem_public_key(pem_public_key.encode())
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def rsa_decrypt(cipher: bytes, pem_private_key: str):
    private_key = serialization.load_pem_private_key(
        pem_private_key.encode(), password=None
    )
    plaintext = private_key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def build_message(msg_type, body):
    return f"{msg_type}\n{body}"


def find_free_port(start_port=12001, end_port=65535):
    for port in range(start_port, end_port + 1):
        with socket(AF_INET, SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    return None


def connect_socket(name, port):
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((name, port))
    return client_socket


def update_algorithm_selection(mode, algorithm, dalgorithm, padding):
    config = load_config()
    config["mode"] = mode
    config["algorithm"] = algorithm
    config["dalgorithm"] = dalgorithm
    config["padding"] = padding

    with open("config.json", "w") as f:
        json.dump(
            {
                "mode": config["mode"],
                "algorithm": config["algorithm"],
                "dalgorithm": config["dalgorithm"],
                "padding": config["padding"],
                "block_size": config["block_size"],
                "key": base64.b64encode(config["key"]).decode(),
                "IV": base64.b64encode(config["IV"]).decode(),
            },
            f,
            indent=4,
        )


def update_key_iv(key, iv):
    config = load_config()
    config["key"] = key
    config["IV"] = iv

    with open("config.json", "w") as f:
        json.dump(
            {
                "mode": config["mode"],
                "algorithm": config["algorithm"],
                "dalgorithm": config.get("dalgorithm"),
                "padding": config["padding"],
                "block_size": config["block_size"],
                "key": base64.b64encode(key).decode(),
                "IV": base64.b64encode(iv).decode(),
            },
            f,
            indent=4,
        )


def send_to_someone(host, port, msg_type, body):
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((host, port))
        s.send(build_message(msg_type, body).encode())
        s.close()
    except Exception as e:
        print("failed sending:", e)


def negotiate_algorithm(peer_list_str):
    peer = peer_list_str.split(",")

    for mode in SUPPORTED_MODES:
        if mode in peer:
            for algo in SUPPORTED_ALGOS:
                if algo in peer:
                    for dalgo in SUPPORTED_DALGOS:
                        if dalgo in peer:
                            for pad in SUPPORTED_PADDINGS:
                                if pad in peer:
                                    return mode, algo, dalgo, pad

    return None


def my_listen(client_socket):
    global RUNNING, THEIR_HALF_SECRET

    while RUNNING:
        conn_socket, addr = client_socket.accept()
        conn_socket.settimeout(None)
        message = conn_socket.recv(4096).decode()
        lines = message.split("\n")
        message_type = lines[0].strip()
        body = "\n".join(lines[1:]).strip()

        match message_type:

            case "hello":
                peer_list = body
                mode, algo, dalgo, pad = negotiate_algorithm(peer_list)
                update_algorithm_selection(mode, algo, dalgo, pad)
                print("received hello from another client")

            case "half_secret":
                try:
                    encrypted_bytes = bytes.fromhex(body)
                    encrypted_bytes = bytes.fromhex(body)
                    received_half = rsa_decrypt(encrypted_bytes, OWN_PRIV_KEY)
                    THEIR_HALF_SECRET = received_half

                    if OWN_HALF_SECRET is not None and THEIR_HALF_SECRET is not None:
                        combined1 = OWN_HALF_SECRET + THEIR_HALF_SECRET
                        combined2 = THEIR_HALF_SECRET + OWN_HALF_SECRET
                        digest1 = hashes.Hash(hashes.SHA256())
                        digest1.update(combined1)
                        full1 = digest1.finalize()
                        digest2 = hashes.Hash(hashes.SHA256())
                        digest2.update(combined2)
                        full2 = digest2.finalize()
                        final_key = full1[:16]
                        final_iv = full2[:16]
                        update_key_iv(final_key, final_iv)
                        print("symmetric key + IV successfully derived")
                except Exception as e:
                    print("error decrypting half secret:", e)
                print("received half secret")

            case "message":
                print("received encrypted message")
                try:
                    ciphertext = bytes.fromhex(body)
                    plaintext = decrypt(ciphertext)
                    print("DECRYPTED MESSAGE:", plaintext.decode())
                except Exception as e:
                    print("error decrypting message:", e)

            case "bye":
                print("received bye from other client")
                RUNNING = False
                client_socket.close()
                return

        conn_socket.close()


def my_send():
    global RUNNING, OTHER_CLIENT_ID, OWN_PUB_KEY, OWN_PRIV_KEY, THEIR_PUBLIC_KEY, OWN_HALF_SECRET

    while RUNNING:
        command = input()

        if not RUNNING:
            break

        match command:
            case "1":
                OWN_PUB_KEY, OWN_PRIV_KEY = generate_rsa_keys()
                message_body = f"{str(OWN_ID)}\n{OWN_PUB_KEY}"
                send_to_someone(SERVER_NAME, SERVER_PORT, "register", message_body)
                print("registered public key with server")

            case "2":
                OTHER_CLIENT_ID = input("other client id: ")
                conn_socket = connect_socket(SERVER_NAME, SERVER_PORT)
                message = build_message("get_key", str(OTHER_CLIENT_ID))
                conn_socket.send(message.encode())

                response = conn_socket.recv(4096).decode()
                lines = response.split("\n")
                message_type = lines[0].strip()
                message_body = "\n".join(lines[1:]).strip()

                if message_type == "set_key":
                    print(f"got public key for client {OTHER_CLIENT_ID} from server")
                    THEIR_PUBLIC_KEY = message_body

                conn_socket.close()

            case "3":
                if OTHER_CLIENT_ID is None:
                    print("no peer selected")
                    continue

                algo_list = ",".join(
                    SUPPORTED_MODES
                    + SUPPORTED_ALGOS
                    + SUPPORTED_DALGOS
                    + SUPPORTED_PADDINGS
                )
                send_to_someone(CLIENT_NAME, int(OTHER_CLIENT_ID), "hello", algo_list)
                print("sent hello")

            case "4":
                OWN_HALF_SECRET = os.urandom(16)
                encrypted_half = rsa_encrypt(OWN_HALF_SECRET, THEIR_PUBLIC_KEY)
                send_to_someone(
                    CLIENT_NAME,
                    int(OTHER_CLIENT_ID),
                    "half_secret",
                    encrypted_half.hex(),
                )
                print("half secret sent")

                if OWN_HALF_SECRET is not None and THEIR_HALF_SECRET is not None:
                    combined1 = OWN_HALF_SECRET + THEIR_HALF_SECRET
                    combined2 = THEIR_HALF_SECRET + OWN_HALF_SECRET
                    digest1 = hashes.Hash(hashes.SHA256())
                    digest1.update(combined1)
                    full1 = digest1.finalize()
                    digest2 = hashes.Hash(hashes.SHA256())
                    digest2.update(combined2)
                    full2 = digest2.finalize()
                    final_key = full1[:16]
                    final_iv = full2[:16]
                    update_key_iv(final_key, final_iv)
                    print("symmetric key + IV successfully derived")

            case "5":

                msg = input("enter message: ")
                ciphertext = encrypt(msg.encode())
                send_to_someone(
                    CLIENT_NAME, int(OTHER_CLIENT_ID), "message", ciphertext.hex()
                )
                print("encrypted message sent")

            case "6":
                if OTHER_CLIENT_ID:
                    try:
                        conn_socket = connect_socket(CLIENT_NAME, int(OTHER_CLIENT_ID))
                        message = build_message("bye", "")
                        conn_socket.send(message.encode())
                        conn_socket.close()
                        print(f"sent bye to client {OTHER_CLIENT_ID}")
                    except:
                        print("peer was not reachable")

                RUNNING = False
                return

            case _:
                print("invalid option")


def main():
    global OWN_ID
    OWN_ID = find_free_port()
    if not OWN_ID:
        print("could not find free port exiting")
        return

    print("my id is", OWN_ID)

    client_port = int(OWN_ID)

    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    client_socket.bind(("", client_port))
    client_socket.listen(1)

    print(
        """options:
            press 1 to register to the key server
            press 2 to get public key of another client
            press 3 to send hello or acknowledgement to another client
            press 4 to send half secret to another client
            press 5 to send encrypted message to another client
            press 6 to send bye"""
    )

    listen_thread = threading.Thread(
        target=my_listen, args=(client_socket,), daemon=True
    )
    listen_thread.start()
    my_send()


if __name__ == "__main__":
    main()
