from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def pemToPublicKey(pem_public_key: bytes) -> EllipticCurvePublicKey | RSAPublicKey:
    """
    Converte uma chave pública em formato PEM para um objeto de chave pública.

    :param pem_public_key: A chave pública em formato PEM.
    :return: Um objeto de chave pública que pode ser EllipticCurvePublicKey ou RSAPublicKey.
    :raises Exception: Se a chave pública não for do tipo esperado.
    """
    public_key = serialization.load_pem_public_key(
        pem_public_key, backend=default_backend()
    )
    if not isinstance(public_key, EllipticCurvePublicKey) and not isinstance(
        public_key, RSAPublicKey
    ):
        raise Exception
    return public_key


def publicKeyToPem(public_key: EllipticCurvePublicKey | RSAPublicKey) -> bytes:
    """
    Converte um objeto de chave pública para o formato PEM.

    :param public_key: Um objeto de chave pública que pode ser EllipticCurvePublicKey ou RSAPublicKey.
    :return: A chave pública em formato PEM.
    """
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_public_key
