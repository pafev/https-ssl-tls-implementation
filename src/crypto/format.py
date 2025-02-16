from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def pemToPublicKey(pem_public_key: bytes) -> EllipticCurvePublicKey | RSAPublicKey:
    public_key = serialization.load_pem_public_key(
        pem_public_key, backend=default_backend()
    )
    if not isinstance(public_key, EllipticCurvePublicKey) and not isinstance(
        public_key, RSAPublicKey
    ):
        raise Exception
    return public_key


def publicKeyToPem(public_key: EllipticCurvePublicKey | RSAPublicKey) -> bytes:
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_public_key
