from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers import algorithms


def get_cipher(key: bytes, iv: bytes) -> tuple:
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.CFB(iv))
    return cipher.encryptor(), cipher.decryptor()
