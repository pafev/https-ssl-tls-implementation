import socket
from threading import Thread


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

    def receive_messages(self) -> None:
        while self.running:
            try:
                message = self.socket.recv(1024).decode("utf-8")
                if not message:
                    break
                print(f"\nResposta do servidor: {message}")
            except Exception as e:
                print(f"Erro ao receber resposta do servidor: {e}")
                self.running = False
                break

    def send_messages(self) -> None:
        while self.running:
            try:
                message = input(
                    "Digite uma mensagem para o servidor (ou 'sair' para encerrar sessão): "
                )
                if message.lower() == "sair":
                    break
                self.socket.send(message.encode("utf-8"))
            except Exception as e:
                print(f"Erro ao enviar mensagem para o servidor: {e}")
                self.running = False
                break

    def start(self) -> None:
        if self.connect():
            try:
                receive_thread = Thread(target=self.receive_messages)
                receive_thread.start()
                send_thread = Thread(target=self.send_messages)
                send_thread.start()
            except Exception:
                print("Erro ao comecar operacao do cliente")
                self.disconnect()

    def disconnect(self) -> None:
        self.socket.close()
        self.running = False
        print("Desconectado do servidor")


client = Client()
client.start()
