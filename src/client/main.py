import socket
import json
import random

from cryptography.hazmat.primitives.asymmetric import ec
from crypto.format import pemToPublicKey, publicKeyToPem
from crypto.gen_keys import derive_key, gen_exchange_keys
from crypto.encryption import get_cipher


class Client:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False
        self.session_key = None

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

    def tls_handshake(self) -> None:
        client_random = str(random.randbytes(32))
        private_key, public_key = gen_exchange_keys()
        client_hello = {
            "version": "TLS 1.3",
            "client random": client_random,
            "cipher algorithms": [
                "AES_128",
                "AES_256",
            ],
            "key share": str(publicKeyToPem(public_key=public_key)),
        }
        self.socket.send(json.dumps(client_hello).encode("utf-8"))
        server_hello = json.loads(self.socket.recv(2048).decode("utf-8"))
        if not server_hello["certificate"]["trusted ca"]:
            raise Exception
        peer_public_key = pemToPublicKey(
            pem_public_key=eval(server_hello["certificate"]["public key"])
        )
        shared_key = private_key.exchange(
            algorithm=ec.ECDH(), peer_public_key=peer_public_key
        )
        self.session_key = derive_key(
            shared_key=shared_key,
            info=eval(client_random) + eval(server_hello["server random"]),
        )

    def send_http_request(self, encrypt, decrypt) -> None:
        try:
            request = {
                "headers": {},
                "method": "GET",
            }
            encrypted_request = (
                encrypt.update(json.dumps(request).encode("utf-8")) + encrypt.finalize()
            )
            self.socket.send(encrypted_request)
        except Exception as e:
            print(f"Erro ao enviar requisicao http ao servidor: {e}")
            self.running = False

    def receive_http_response(self, decrypt) -> None:
        try:
            encrypted_response = self.socket.recv(1024)
            if not encrypted_response:
                raise Exception
            response = (decrypt.update(encrypted_response) + decrypt.finalize()).decode(
                "utf-8"
            )
            print(f"Resposta do servidor:\n\t{response}")
        except Exception as e:
            print(f"Erro ao carregar resposta http do servidor: {e}")
            self.running = False

    def run(self) -> None:
        if self.connect():
            try:
                self.tls_handshake()
                if self.session_key:
                    encrypt, decrypt = get_cipher(self.session_key)
                    self.send_http_request(encrypt, decrypt)
                    self.receive_http_response(decrypt)
            except Exception as e:
                print(f"Erro ao comecar operacao do cliente: {e}")
                self.disconnect()

    def disconnect(self) -> None:
        self.socket.close()
        self.running = False
        print("Desconectado do servidor")


if __name__ == "__main__":
    client = Client()
    client.run()
