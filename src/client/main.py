import socket
import json


class Client:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False

    def connect(self, server_host="localhost", server_port=5443) -> bool:
        try:
            server_address = (server_host, server_port)
            print(f"Se conectando ao servidor {server_address}")
            self.socket.connect(server_address)
            self.running = True

            return True
        except Exception as e:
            print(f"Erro ao se conectar com servidor: {e}")
            return False

    def send_http_request(self) -> None:
        try:
            request = {
                "headers": {},
                "method": "GET",
            }
            self.socket.send(json.dumps(request).encode("utf-8"))
        except Exception as e:
            print(f"Erro ao enviar requisicao http ao servidor{e}")
            self.running = False

    def receive_http_response(self) -> None:
        try:
            response = json.loads(self.socket.recv(1024).decode())
            if not response:
                raise Exception
            print(f"Resposta do servidor:\n{response}")
        except Exception as e:
            print(f"Erro ao carregar resposta http do servidor: {e}")
            self.running = False

    def run(self) -> None:
        if self.connect():
            try:
                self.send_http_request()
                self.receive_http_response()
            except Exception:
                print("Erro ao comecar operacao do cliente")
                self.disconnect()

    def disconnect(self) -> None:
        self.socket.close()
        self.running = False
        print("Desconectado do servidor")


if __name__ == "__main__":
    client = Client()
    client.run()
