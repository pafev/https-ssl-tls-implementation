from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.base import (
    _CipherContext,
    _AEADEncryptionContext,
    _AEADCipherContext,
)


def get_cipher(
    key: bytes,
) -> tuple[
    _AEADEncryptionContext | _AEADCipherContext | _CipherContext,
    _AEADEncryptionContext | _AEADCipherContext | _CipherContext,
]:
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.CFB(b"a" * 16))
    return cipher.encryptor(), cipher.decryptor()
