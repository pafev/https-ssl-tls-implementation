import socket
from threading import Thread


class Server:
    def __init__(self, host="localhost", port=5443) -> None:
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.clients = []

    def start(self):
        server_address = (self.host, self.port)
        self.socket.bind(server_address)
        self.socket.listen(5)
        print(f"Servidor escutando em {self.host}, na porta {self.port}")

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

    def handle_client(self, client_socket, client_address):
        try:
            while self.running:
                data = client_socket.recv(1024).decode("utf-8")
                if not data:
                    break
                print(f"Mensagem recebida do cliente {client_address}: {data}")
                response = "Mensagem recebida"
                client_socket.send(response.encode("utf-8"))
        except Exception as e:
            print(f"Aconteceu um erro ao lidar com cliente {client_address}: {e}")
        finally:
            self.remove_client(client_socket)

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            self.clients.remove(client_socket)
            client_socket.close()

    def stop(self):
        for client in self.clients:
            client.close()
        self.running = False
        self.socket.close()


server = Server()
server.start()
