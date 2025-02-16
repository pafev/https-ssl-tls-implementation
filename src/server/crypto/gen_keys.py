from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def gen_exchange_keys():
    curve = ec.SECT163R2
    private_key = ec.generate_private_key(curve=curve(), backend=default_backend())
    public_key = private_key.public_key()

    return private_key, public_key


def derive_key(shared_key: bytes, info: bytes) -> bytes:
    derived_key = HKDF(
        algorithm=hashes.SHA3_256(), length=32, salt=None, info=info
    ).derive(shared_key)
    return derived_key
