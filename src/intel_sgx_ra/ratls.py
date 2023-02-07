"""intel_sgx_ra.ratls module."""

import hashlib
import logging
import ssl
from pathlib import Path
from typing import Union, cast

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from intel_sgx_ra.error import RATLSVerificationError, SGXQuoteNotFound
from intel_sgx_ra.quote import Quote

SGX_QUOTE_EXTENSION_OID = x509.ObjectIdentifier("1.2.840.113741.1337.6")


def get_quote_from_cert(ratls_cert: Union[bytes, x509.Certificate]) -> Quote:
    """Extract SGX quote from X509 certificate."""
    cert: x509.Certificate = (
        x509.load_pem_x509_certificate(ratls_cert)
        if isinstance(ratls_cert, bytes)
        else ratls_cert
    )

    try:
        quote_extension: x509.UnrecognizedExtension = cast(
            x509.UnrecognizedExtension,
            cert.extensions.get_extension_for_oid(SGX_QUOTE_EXTENSION_OID).value,
        )
    except x509.extensions.ExtensionNotFound as exc:
        raise SGXQuoteNotFound from exc

    return Quote.from_bytes(quote_extension.value)


def ratls_verification(ratls_cert: Union[str, bytes, Path, x509.Certificate]) -> Quote:
    """Check user_report_data in SGX quote to match SHA256(cert.public_key())."""
    cert: x509.Certificate

    if isinstance(ratls_cert, bytes):
        cert = x509.load_pem_x509_certificate(ratls_cert)
    elif isinstance(ratls_cert, str):
        cert = x509.load_pem_x509_certificate(ratls_cert.encode("utf-8"))
    elif isinstance(ratls_cert, Path):
        cert = x509.load_pem_x509_certificate(ratls_cert.read_bytes())
    else:
        cert = ratls_cert

    quote: Quote = get_quote_from_cert(cert)
    pk: bytes = cert.public_key().public_bytes(
        encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
    )
    success: bool = hashlib.sha256(pk).digest() == quote.report_body.report_data[:32]

    logging.info(
        "[ %4s ] ra-tls verification of public key", "OK" if success else "FAIL"
    )

    if not success:
        raise RATLSVerificationError

    return quote


def ratls_verification_from_url(url: str) -> Quote:
    """RA-TLS verification from HTTPS URL."""
    hostname: str = url.lstrip("https://")
    port: str = "443"

    if ":" in hostname:
        hostname, port = hostname.split(":")

    ca_data: bytes = ssl.get_server_certificate((hostname, int(port))).encode("utf-8")
    ratls_cert: x509.Certificate = x509.load_pem_x509_certificate(ca_data)

    return ratls_verification(ratls_cert)
