from socket import *


def build_message(msg_type, body):
    return f"{msg_type}\n{body}"


def listen_and_send(server_socket, key_dictionary):
    while True:
        conn_socket, addr = server_socket.accept()

        message = conn_socket.recv(4096).decode()
        lines = message.split("\n")
        message_type = lines[0].strip()
        message_body = "\n".join(lines[1:]).strip()
        if message_type == "get_key":
            key = key_dictionary[int(message_body)]
            response = build_message("set_key", key)
            conn_socket.send(response.encode())
            print("server was asked to provide public key for: ", message_body)
        else:  ## "register"
            client_id, client_key = message_body.split("\n", 1)
            key_dictionary[int(client_id)] = client_key
            print("server received registration from: ", client_id)
        conn_socket.close()


def main():
    server_port = 12000
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(("", server_port))
    server_socket.listen(1)
    print("The server is ready")
    key_dictionary = {}
    listen_and_send(server_socket, key_dictionary)


if __name__ == "__main__":
    main()
