from socket import *
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

RUNNING = True
OTHER_CLIENT_ID = None
OWN_PUB_KEY = None
OWN_PRIV_KEY = None
THEIR_PUBLIC_KEY = None


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


def my_listen(client_socket, client_id):
    global RUNNING

    while RUNNING:
        conn_socket, addr = client_socket.accept()
        conn_socket.settimeout(None)
        message = conn_socket.recv(4096).decode()
        lines = message.split("\n")
        message_type = lines[0].strip()

        match message_type:
            case "hello":
                print("received hello from another client")
            case "ack":
                print("received ack from another client")
            case "half_secret":
                print("received half secret")
            case "message":
                print("received encrypted message")
            case "bye":
                print("received bye from other client")
                RUNNING = False
                client_socket.close()
                return

        conn_socket.close()


def my_send(server_name, server_port, client_own_id, client_name):
    global RUNNING, OTHER_CLIENT_ID, OWN_PUB_KEY, OWN_PRIV_KEY, THEIR_PUBLIC_KEY

    while RUNNING:
        command = input()

        if not RUNNING:
            break

        match command:
            case "1":
                OWN_PUB_KEY, OWN_PRIV_KEY = generate_rsa_keys()
                conn_socket = connect_socket(server_name, server_port)
                message_body = f"{str(client_own_id)}\n{OWN_PUB_KEY}"
                message = build_message("register", message_body)
                conn_socket.send(message.encode())
                conn_socket.close()
                print("registered public key with server")

            case "2":
                OTHER_CLIENT_ID = input("other client id: ")
                conn_socket = connect_socket(server_name, server_port)
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
                print("not implemented yet")

            case "5":
                print("not implemented yet")

            case "4":
                print("not implemented yet")

            case "6":
                if OTHER_CLIENT_ID:
                    try:
                        conn_socket = connect_socket(client_name, int(OTHER_CLIENT_ID))
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
    client_id = find_free_port()
    if not client_id:
        print("could not find free port exiting")
        return

    print("my id is", client_id)

    server_name = "localhost"
    client_name = "localhost"
    server_port = 12000
    client_port = int(client_id)

    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    client_socket.bind(("", client_port))
    client_socket.listen(1)

    print(
        """options:
            press 1 to register to the key server
            press 2 to get public key of another client
            press 3 to send hello to another client
            press 4 to send half secret to another client
            press 5 to send encrypted message to another client
            press 6 to send bye"""
    )

    listen_thread = threading.Thread(
        target=my_listen, args=(client_socket, client_id), daemon=True
    )
    listen_thread.start()
    my_send(server_name, server_port, client_id, client_name)


if __name__ == "__main__":
    main()
