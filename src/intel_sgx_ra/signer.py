"""intel_sgx_ra.signer module."""

import hashlib
from pathlib import Path
from typing import Union, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from intel_sgx_ra.error import CryptoKeyError


def mr_signer_from_pk(public_key: Union[RSAPublicKey, Path, bytes]) -> bytes:
    """Compute MRSIGNER value from RSA public key.

    Parameters
    ----------
    public_key : Union[RSAPublicKey, Path, bytes]
        RSA public key to compute MRSIGNER value.

    Returns
    -------
    bytes
        MRSIGNER which is the SHA256 digest of RSA public key modulus.

    """
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


def mr_signer_from_cert(ratls_cert: Union[str, bytes, Path, x509.Certificate]) -> bytes:
    """Compute MRSIGNER from X.509 certificate.

    Parameters
    ----------
    ratls_cert : Union[str, bytes, Path, x509.Certificate]
        X.509 RA-TLS certificate containing Intel SGX quote.

    Returns
    -------
    bytes
        MRSIGNER which is the SHA256 digest of RSA public key modulus.

    """
    cert: x509.Certificate

    if isinstance(ratls_cert, bytes):
        cert = x509.load_pem_x509_certificate(ratls_cert)
    elif isinstance(ratls_cert, str):
        cert = x509.load_pem_x509_certificate(ratls_cert.encode("utf-8"))
    elif isinstance(ratls_cert, Path):
        cert = x509.load_pem_x509_certificate(ratls_cert.read_bytes())
    else:
        cert = ratls_cert

    if not isinstance(cert.public_key(), RSAPublicKey):
        raise CryptoKeyError("Certificate does not contain an RSA public key")

    return mr_signer_from_pk(cast(RSAPublicKey, cert.public_key()))
