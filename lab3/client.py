from socket import *


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


def main():
    client_id = find_free_port()
    server_name = "localhost"
    server_port = 12000
    print(
        """Options:
            Press 1 to: ask for public key
            Press 2 to: register to the key server
            Press 3 to: get public key of another client
            Press 4 to: send hello to another client
            Press 5 to: send half secret to another client
            Press 6 to: send encrypted message to another client
            Press 7 to: send bye"""
    )

    while True:
        command = input()
        match command:
            case "1":
                socket = connect_socket(server_name, server_port)
                socket.send(str(client_id).encode())
            case "2":
                socket = connect_socket(server_name, server_port)
            case "3":
                break
            case "4":
                break
            case "5":
                break
            case "6":
                break
            case "7":
                break
        socket.close()
        break


if __name__ == "__main__":
    main()
