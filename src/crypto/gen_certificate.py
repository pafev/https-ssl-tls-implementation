import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from crypto.format import pemToPublicKey, publicKeyToPem


def gen_certificate(country: str, state: str, org: str, common_host: str) -> dict:
    certificate = {
        "data": {
            "country": country,
            "state": state,
            "org": org,
            "common_host": common_host,
        }
    }
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = private_key.sign(
        data=json.dumps(certificate["data"]).encode("utf-8"),
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA3_256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA3_256(),
    )
    pem_public_key = publicKeyToPem(public_key=private_key.public_key())
    certificate["validation"] = {
        "signature": signature.hex(),
        "public key": pem_public_key.hex(),
    }
    return certificate


def verify_certificate(certificate: dict):
    public_key = pemToPublicKey(
        pem_public_key=bytes.fromhex(certificate["validation"]["public key"])
    )
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise Exception

    public_key.verify(
        signature=bytes.fromhex(certificate["validation"]["signature"]),
        data=json.dumps(certificate["data"]).encode("utf-8"),
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA3_256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA3_256(),
    )
