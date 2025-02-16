import json
import socket
from threading import Thread


class Server:
    def __init__(self, host="localhost", port=5443) -> None:
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.clients = []

    def init_server(self) -> None:
        server_address = (self.host, self.port)
        self.socket.bind(server_address)
        self.socket.listen(5)
        print(f"Servidor escutando em {self.host}, na porta {self.port}")

    def run(self) -> None:
        self.init_server()
        try:
            while self.running:
                client_socket, client_address = self.socket.accept()
                print(f"Nova conexão de cliente: {client_address}")
                client_thread = Thread(
                    target=self.handle_client, args=(client_socket, client_address)
                )
                client_thread.start()
                self.clients.append(client_socket)
        except KeyboardInterrupt:
            print("\nInterrompendo servidor")
        finally:
            self.stop()

    def handle_http_request(self, client_socket, client_address) -> None:
        request = client_socket.recv(1024).decode("utf-8")
        if not request:
            raise Exception
        print(f"Requisição recebida do cliente {client_address}: {request}")
        response = {
            "status": 200,
            "body": "",
        }
        client_socket.send(json.dumps(response).encode("utf-8"))

    def handle_client(self, client_socket, client_address) -> None:
        try:
            self.handle_http_request(client_socket, client_address)
        except Exception as e:
            print(f"Aconteceu um erro ao lidar com cliente {client_address}: {e}")
        finally:
            self.remove_client(client_socket)

    def remove_client(self, client_socket) -> None:
        if client_socket in self.clients:
            self.clients.remove(client_socket)
            client_socket.close()

    def stop(self):
        for client in self.clients:
            client.close()
        self.running = False
        self.socket.close()


if __name__ == "__main__":
    server = Server()
    server.run()
