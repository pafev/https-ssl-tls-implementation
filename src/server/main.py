import json
import os
import socket
from threading import Thread

from cryptography.hazmat.primitives.asymmetric import ec

from crypto.gen_certificate import gen_certificate
from crypto.gen_keys import derive_key, gen_exchange_keys
from crypto.format import pemToPublicKey, publicKeyToPem
from crypto.encryption import get_cipher


class Server:
    """Classe que representa um servidor que aceita conexões de clientes e realiza comunicação segura."""

    def __init__(self, host="localhost", port=5443) -> None:
        """
        Inicializa o servidor com o endereço e porta especificados.

        :param host: Endereço do servidor.
        :param port: Porta do servidor.
        """
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.clients = []
        self.certificate = gen_certificate(
            country="BR", state="Brasilia-DF", org="pafev", common_host="localhost:5443"
        )

    def init_server(self) -> None:
        """Inicializa o servidor, vinculando o endereço e porta e começando a escutar por conexões."""
        server_address = (self.host, self.port)
        self.socket.bind(server_address)
        self.socket.listen(5)
        print(f"Servidor escutando em {self.host}, na porta {self.port}")

    def run(self) -> None:
        """Executa o servidor, aceitando novas conexões de clientes e criando threads para cada cliente."""
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

    def tls_handshake(self, client_socket, client_address) -> dict:
        """
        Realiza o handshake TLS com o cliente, estabelecendo uma sessão segura.

        :param client_socket: Socket do cliente.
        :param client_address: Endereço do cliente.
        :return: Dicionário contendo informações do cliente, como socket, chave de sessão e cifra.
        """
        # Wait for client hello and verify compatibility
        client_hello = json.loads(client_socket.recv(2048).decode("utf-8"))
        if (
            client_hello["version"] != "TLS 1.3"
            or "AES_256" not in client_hello["cipher algorithms"]
        ):
            raise Exception

        # Generate server random, session key and cipher for encrypt and decrypt
        server_random = os.urandom(16)
        private_key, public_key = gen_exchange_keys()
        peer_public_key = pemToPublicKey(
            pem_public_key=bytes.fromhex(client_hello["extensions"]["key share"])
        )
        if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
            raise Exception
        shared_key = private_key.exchange(
            algorithm=ec.ECDH(), peer_public_key=peer_public_key
        )
        session_key = derive_key(
            shared_key,
            info=bytes.fromhex(client_hello["client random"]) + server_random,
        )
        cipher = get_cipher(
            key=session_key, iv=bytes.fromhex(client_hello["extensions"]["iv"])
        )

        # Mount server hello message and send to client
        server_hello = {
            "certificate": self.certificate,
            "server random": server_random.hex(),
            "extensions": {"key share": publicKeyToPem(public_key=public_key).hex()},
        }
        client_socket.send(json.dumps(server_hello).encode("utf-8"))

        # Adds client to list of handled clients on the server
        client = {
            "socket": client_socket,
            "session key": session_key,
            "cipher": cipher,
            "address": client_address,
        }
        self.clients.append(client)

        return client

    def handle_http_request(self, client) -> None:
        """
        Lida com a requisição HTTP do cliente, descriptografando-a, processando-a e enviando uma resposta.

        :param client: Dicionário contendo informações do cliente.
        """
        client_address = client["address"]
        encrypt, decrypt = client["cipher"]
        client_socket = client["socket"]

        # Wait for encrypted request from client
        encrypted_request = client_socket.recv(1024)
        if not encrypted_request:
            raise Exception
        print(
            f"\nRequisicao criptografada do cliente {client_address}: {encrypted_request}"
        )

        # Decrypt request from client
        request = (decrypt.update(encrypted_request) + decrypt.finalize()).decode(
            "utf-8"
        )
        print(
            f"\nConteudo da requisição http criptografada recebida do cliente {client_address}:{request}"
        )

        # Mount response and sends it to the client
        response = {
            "version": "HTTP/1.1",
            "status": "200 OK",
            "headers": {
                "Server": "self_https.server",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
            "body": {"message": "Hello World"},
        }
        print(f"\nConteudo da resposta http ao cliente: {response}")
        encrypted_response = (
            encrypt.update(json.dumps(response).encode("utf-8")) + encrypt.finalize()
        )
        client["socket"].send(encrypted_response)
        print(f"\nResposta criptografada enviada ao cliente: {encrypted_response}")

    def handle_client(self, client_socket, client_address) -> None:
        """
        Lida com a comunicação com o cliente, realizando o handshake TLS e processando requisições HTTP.

        :param client_socket: Socket do cliente.
        :param client_address: Endereço do cliente.
        """
        try:
            client = self.tls_handshake(client_socket, client_address)
            try:
                self.handle_http_request(client)
            except Exception as e:
                print(f"Erro na comunicação https com o cliente {client_address}: {e}")
                self.remove_client(client)
        except Exception as e:
            print(f"Erro no handshake tls com o cliente {client_address}: {e}")

    def remove_client(self, client) -> None:
        """
        Remove o cliente da lista de clientes e fecha o socket associado.

        :param client: Dicionário contendo informações do cliente.
        """
        if client in self.clients:
            self.clients.remove(client)
            client["socket"].close()

    def stop(self):
        """Para o servidor, fechando todos os sockets de clientes e o socket do servidor."""
        for client in self.clients:
            client["socket"].close()
        self.running = False
        self.socket.close()


if __name__ == "__main__":
    server = Server()
    server.run()
