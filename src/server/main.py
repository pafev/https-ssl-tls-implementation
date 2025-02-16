import json
import random
import socket
from threading import Thread

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from crypto.gen_keys import derive_key, gen_exchange_keys
from crypto.format import pemToPublicKey, publicKeyToPem


class Server:
    def __init__(self, host="localhost", port=5443) -> None:
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.clients = []
        self.certificate = {"public key": None, "trusted ca": True}

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
        except KeyboardInterrupt:
            print("\nInterrompendo servidor")
        finally:
            self.stop()

    def tls_handshake(self, client_socket) -> dict:
        client_hello = json.loads(client_socket.recv(2048).decode("utf-8"))
        if (
            client_hello["version"] != "TLS 1.3"
            or "AES_256" not in client_hello["cipher algorithms"]
        ):
            raise Exception
        server_random = str(random.randbytes(32))
        private_key, self_public_key = gen_exchange_keys()
        peer_public_key = pemToPublicKey(pem_public_key=eval(client_hello["key share"]))
        shared_key = private_key.exchange(
            algorithm=ec.ECDH(), peer_public_key=peer_public_key
        )
        session_key = derive_key(
            shared_key, info=eval(client_hello["client random"]) + eval(server_random)
        )
        self.certificate["public key"] = str(publicKeyToPem(public_key=self_public_key))
        server_hello = {"certificate": self.certificate, "server random": server_random}
        client_socket.send(json.dumps(server_hello).encode("utf-8"))
        client = {"socket": client_socket, "session key": session_key}
        self.clients.append(client)
        return client

    def handle_http_request(self, client, client_address) -> None:
        request = client["socket"].recv(1024).decode("utf-8")
        if not request:
            raise Exception
        print(f"Requisição recebida do cliente {client_address}: {request}")
        response = {
            "status": 200,
            "body": "",
        }
        client["socket"].send(json.dumps(response).encode("utf-8"))

    def handle_client(self, client_socket, client_address) -> None:
        try:
            client = self.tls_handshake(client_socket)
            try:
                self.handle_http_request(client, client_address)
            except Exception as e:
                print(f"Erro na comunicação https com o cliente {client_address}: {e}")
                self.remove_client(client)
        except Exception as e:
            print(f"Erro no handshake tls com o cliente {client_address}: {e}")

    def remove_client(self, client) -> None:
        if client in self.clients:
            self.clients.remove(client)
            client["socket"].close()

    def stop(self):
        for client in self.clients:
            client["socket"].close()
        self.running = False
        self.socket.close()


if __name__ == "__main__":
    server = Server()
    server.run()
