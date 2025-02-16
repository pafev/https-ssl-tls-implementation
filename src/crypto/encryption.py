from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers import algorithms


def get_cipher(key: bytes, iv: bytes) -> tuple:
    """
    Cria um par de objetos de cifra para criptografia e descriptografia usando AES no modo CFB.

    :param key: A chave de criptografia AES. Deve ter um tamanho apropriado para o algoritmo AES (por exemplo, 16, 24 ou 32 bytes).
    :param iv: O vetor de inicialização (IV) para o modo CFB. Deve ter 16 bytes de comprimento.
    :return: Uma tupla contendo o objeto de criptografia (encryptor) e o objeto de descriptografia (decryptor).
    """
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.CFB(iv))
    return cipher.encryptor(), cipher.decryptor()
