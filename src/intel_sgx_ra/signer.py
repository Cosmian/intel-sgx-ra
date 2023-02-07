"""intel_sgx_ra.signer module."""

import hashlib
from pathlib import Path
from typing import Union, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from intel_sgx_ra.error import CryptoKeyError


def mr_signer_from_pk(public_key: Union[RSAPublicKey, Path, bytes]) -> bytes:
    """Compute MRSIGNER from RSA public key."""
    pk: RSAPublicKey

    if isinstance(public_key, bytes):
        pk = cast(RSAPublicKey, load_pem_public_key(data=public_key))
    elif isinstance(public_key, Path):
        pk = cast(RSAPublicKey, load_pem_public_key(data=Path(public_key).read_bytes()))
    else:
        pk = public_key

    modulus: bytes = pk.public_numbers().n.to_bytes(
        pk.key_size // 8, byteorder="little"
    )

    return hashlib.sha256(modulus).digest()


def mr_signer_from_cert(certificate: Union[x509.Certificate, Path, bytes]) -> bytes:
    """Compute MRSIGNER from X.509 certificate."""
    cert: x509.Certificate

    if isinstance(certificate, bytes):
        cert = cast(x509.Certificate, x509.load_pem_x509_certificate(data=certificate))
    elif isinstance(certificate, Path):
        cert = cast(
            x509.Certificate,
            x509.load_pem_x509_certificate(data=Path(certificate).read_bytes()),
        )
    else:
        cert = certificate

    if not isinstance(cert.public_key(), RSAPublicKey):
        raise CryptoKeyError("Certificate public key must be RSA public key")

    return mr_signer_from_pk(cast(RSAPublicKey, cert.public_key()))
