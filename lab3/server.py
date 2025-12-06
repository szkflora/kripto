from socket import *

server_port = 12000
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
server_socket.bind(("", server_port))
server_socket.listen(1)
print("The server is ready")

key_dictionary = {}


def create_pub_key():
    print()


while True:
    connection_socket, addr = server_socket.accept()

    request = connection_socket.recv(1024).decode()
    if len(request) == 5:
        print(request)
    else:
        print("hmmmmmmmm")
    connection_socket.close()
    break
