from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers import algorithms


def get_cipher(
    key: bytes,
) -> tuple:
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.CFB(b"a" * 16))
    return cipher.encryptor(), cipher.decryptor()
