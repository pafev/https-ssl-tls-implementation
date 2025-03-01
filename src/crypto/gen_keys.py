from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def gen_exchange_keys():
    """
    Gera um par de chaves para troca de chaves usando curvas elípticas.

    :return: Uma tupla contendo a chave privada e a chave pública geradas.
    """
    curve = ec.SECT163R2
    private_key = ec.generate_private_key(curve=curve(), backend=default_backend())
    public_key = private_key.public_key()

    return private_key, public_key


def derive_key(shared_key: bytes, info: bytes) -> bytes:
    """
    Deriva uma chave simétrica a partir de uma chave compartilhada usando HKDF.

    :param shared_key: A chave compartilhada a partir da qual a chave simétrica será derivada.
    :param info: Informação adicional usada no processo de derivação de chave.
    :return: A chave simétrica derivada.
    """
    derived_key = HKDF(
        algorithm=hashes.SHA3_256(), length=24, salt=None, info=info
    ).derive(shared_key)
    return derived_key
