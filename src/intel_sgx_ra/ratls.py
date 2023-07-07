"""intel_sgx_ra.ratls module."""

import hashlib
import logging
import socket
import ssl
from pathlib import Path
from typing import Tuple, Union, cast
from urllib.parse import ParseResult, urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from intel_sgx_ra import globs
from intel_sgx_ra.error import (
    CertificateError,
    RATLSVerificationError,
    SGXQuoteNotFound,
)
from intel_sgx_ra.quote import Quote

SGX_QUOTE_EXTENSION_OID = x509.ObjectIdentifier("1.2.840.113741.1337.6")


def url_parse(url: str) -> Tuple[str, int]:
    """Parse `url` and output 2-tuple (host, port).

        Parameters
        ----------
        url : str
            URL string of the form:
            <scheme>://<netloc>/<path>;<params>?<query>#<fragment>.
    .
        Returns
        -------
        Tuple[str, int]
            2-tuple (host, port) parsed from `url`.

    """
    result: ParseResult = urlparse(url)

    if result.scheme not in ("http", "https"):
        raise RATLSVerificationError("Only HTTP/HTTPS protocols allowed")

    port: str = "80" if "http" in result.scheme else "443"

    host: str = result.netloc

    if ":" in host:
        host, port = host.split(":")

    return host, int(port)


def get_server_certificate(
    addr: Tuple[str, int], ssl_version=ssl.PROTOCOL_TLS_CLIENT
) -> str:
    """Get TLS certificate from `addr`.

    Parameters
    ----------
    addr : Tuple[str, int]
        2-tuple (host, port).
    ssl_version : ssl._SSLMethod
        SSL protocol version.

    Returns
    -------
    str
        PEM certificate of the server.

    Notes
    -----
    Don't use `ssl.get_server_certificate()` because there are some
    issues with Server Name Indication (SNI) extension on some
    OpenSSL/LibreSSL versions (particularly on MacOS).

    """
    host, port = addr
    with socket.create_connection((host, port), timeout=10) as sock:
        context = ssl.SSLContext(ssl_version)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert(True)
            if not cert:
                raise CertificateError("Can't get peer certificate")
            return ssl.DER_cert_to_PEM_cert(cert)


def get_quote_from_cert(ratls_cert: Union[bytes, x509.Certificate]) -> Quote:
    """Extract SGX quote from X.509 certificate.

    Parameters
    ----------
    ratls_cert : Union[bytes, x509.Certificate]
        X.509 RA-TLS certificate to extract the quote.

    Returns
    -------
    Quote
        Parsed Intel SGX quote from X.509 v3 extension of the certificate.

    """
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


def ratls_verify(ratls_cert: Union[str, bytes, Path, x509.Certificate]) -> Quote:
    """RA-TLS verification of the X.509 certificate.

    It compares the first 32 bytes of `report_data` field in SGX quote
    with SHA256(ratls_cert.public_key()).

    Parameters
    ----------
    ratls_cert : Union[str, bytes, Path, x509.Certificate]
        X.509 RA-TLS certificate to verify.

    Returns
    -------
    Quote
        Parsed Intel SGX quote if success.

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

    quote: Quote = get_quote_from_cert(cert)
    pk: bytes = cert.public_key().public_bytes(
        encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
    )
    success: bool = hashlib.sha256(pk).digest() == quote.report_body.report_data[:32]

    logging.info(
        "%s RA-TLS verification of public key fingerprint",
        globs.OK if success else globs.FAIL,
    )

    if not success:
        raise RATLSVerificationError

    return quote


def ratls_verify_from_url(url: str) -> Quote:
    """RA-TLS verification of the X.509 certificate fetched from `url`.

    Parameters
    ----------
    url : str
        String URL to fetch X.509 certificate for RA-TLS verification.

    Returns
    -------
    Quote
        Parsed Intel SGX quote if success.

    """
    host, port = url_parse(url)  # type: str, int

    ca_data: bytes = get_server_certificate((host, port)).encode("utf-8")
    ratls_cert: x509.Certificate = x509.load_pem_x509_certificate(ca_data)

    return ratls_verify(ratls_cert)
