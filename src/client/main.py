import socket
import json
import os

from cryptography.hazmat.primitives.asymmetric import ec
from crypto.format import pemToPublicKey, publicKeyToPem
from crypto.gen_certificate import verify_certificate
from crypto.gen_keys import derive_key, gen_exchange_keys
from crypto.encryption import get_cipher


class Client:
    """Classe que representa um cliente que se conecta a um servidor e realiza comunicação segura."""

    def __init__(self) -> None:
        """Inicializa o cliente com um socket e variáveis de controle."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False
        self.session_key: bytes = b""
        self.cipher: tuple = ()

    def connect(self, server_host="localhost", server_port=5443) -> bool:
        """
        Conecta ao servidor especificado.

        :param server_host: Endereço do servidor.
        :param server_port: Porta do servidor.
        :return: True se a conexão for bem-sucedida, False caso contrário.
        """
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
        """Realiza o handshake TLS com o servidor para estabelecer uma sessão segura."""
        # Mount client hello for sends it to the server
        client_random = os.urandom(32)
        private_key, public_key = gen_exchange_keys()
        iv_aes = os.urandom(16)
        client_hello = {
            "version": "TLS 1.3",
            "client random": client_random.hex(),
            "cipher algorithms": [
                "AES_128",
                "AES_256",
            ],
            "extensions": {
                "key share": publicKeyToPem(public_key=public_key).hex(),
                "iv": iv_aes.hex(),
            },
        }
        self.socket.send(json.dumps(client_hello).encode("utf-8"))

        # Wait for server hello
        server_hello = json.loads(self.socket.recv(2048).decode("utf-8"))

        # Verify certificate
        verify_certificate(server_hello["certificate"])

        # Generate session key and cipher for encrypt and decrypt
        peer_public_key = pemToPublicKey(
            pem_public_key=bytes.fromhex(server_hello["extensions"]["key share"])
        )
        if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
            raise Exception
        shared_key = private_key.exchange(
            algorithm=ec.ECDH(), peer_public_key=peer_public_key
        )
        self.session_key = derive_key(
            shared_key=shared_key,
            info=client_random + bytes.fromhex(server_hello["server random"]),
        )
        encrypt, decrypt = get_cipher(self.session_key, iv=iv_aes)
        self.cipher = (encrypt, decrypt)

    def send_http_request(self) -> None:
        """Envia uma requisição HTTP ao servidor."""
        try:
            request = {
                "method": "GET",
                "path": "/",
                "version": "HTTP/1.1",
                "headers": {
                    "Host": "localhost:5443",
                    "User-Agent": "self_https/0.1.0",
                    "Accept": "*/*",
                },
            }
            encrypt = self.cipher[0]
            encrypted_req = (
                encrypt.update(json.dumps(request).encode("utf-8")) + encrypt.finalize()
            )
            self.socket.send(encrypted_req)
        except Exception as e:
            print(f"Erro ao enviar requisicao http ao servidor: {e}")
            self.running = False

    def receive_http_response(self) -> None:
        """Recebe a resposta HTTP do servidor e a imprime."""
        try:
            encrypted_res = self.socket.recv(1024)
            if not encrypted_res:
                raise Exception
            print(f"\nResposta criptografa do servidor: {encrypted_res}")
            decrypt = self.cipher[1]
            response = (decrypt.update(encrypted_res) + decrypt.finalize()).decode(
                "utf-8"
            )
            print(f"\nResposta http descriptografada do servidor: {response}")
        except Exception as e:
            print(f"Erro ao carregar resposta http do servidor: {e}")
            self.running = False

    def run(self) -> None:
        """Executa o cliente, conectando e comunicando-se com o servidor."""
        if self.connect():
            try:
                self.tls_handshake()
                if self.session_key and self.cipher:
                    self.send_http_request()
                    self.receive_http_response()
            except Exception as e:
                print(f"Erro ao comecar operacao do cliente: {e}")
                self.disconnect()

    def disconnect(self) -> None:
        """Desconecta do servidor e encerra a conexão."""
        self.socket.close()
        self.running = False
        print("Desconectado do servidor")


if __name__ == "__main__":
    client = Client()
    client.run()
