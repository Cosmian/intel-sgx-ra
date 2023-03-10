"""intel_ra_sgx.attest module."""

import logging
from typing import Union, cast

import cryptography.exceptions
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import HashAlgorithm

from intel_sgx_ra.error import CertificateRevokedError, SGXDebugModeError
from intel_sgx_ra.pcs import get_pck_cert_crl, get_root_ca_crl
from intel_sgx_ra.quote import Quote

# define SGX_FLAGS_DEBUG 0x0000000000000002ULL
SGX_FLAGS_DEBUG: int = 2


def remote_attestation(quote: Union[Quote, bytes], base_url: str):
    """Process DCAP remote attestation with SGX `quote`."""
    quote = cast(Quote, Quote.from_bytes(quote) if isinstance(quote, bytes) else quote)

    # If set, then the enclave is in debug mode
    debug: bool = bool(quote.report_body.flags & SGX_FLAGS_DEBUG)

    logging.info("[ %4s ] SGX enclave not in debug mode", "FAIl" if debug else "OK")

    if debug:
        raise SGXDebugModeError

    pck_cert, pck_platform_ca_cert, root_ca_cert = [
        x509.load_pem_x509_certificate(raw_cert) for raw_cert in quote.certs()
    ]  # type: x509.Certificate, x509.Certificate, x509.Certificate
    _pck_pk, pck_platform_ca_pk, root_ca_pk = (
        cast(ec.EllipticCurvePublicKey, pck_cert.public_key()),
        cast(ec.EllipticCurvePublicKey, pck_platform_ca_cert.public_key()),
        cast(ec.EllipticCurvePublicKey, root_ca_cert.public_key()),
    )

    root_ca_crl: x509.CertificateRevocationList = get_root_ca_crl(base_url)
    # Check that Intel Root CA signed Intel Root CA CRL
    assert root_ca_crl.is_signature_valid(root_ca_pk)
    if root_ca_crl.get_revoked_certificate_by_serial_number(root_ca_cert.serial_number):
        logging.info("[ %4s ] Checking Intel Root CA certificate against CRL", "FAIL")
        raise CertificateRevokedError("Intel Root CA certificate revoked")

    pck_platform_crl = get_pck_cert_crl(base_url, "platform")
    # Check that Intel PCK Platform signed Intel PCK CRL
    assert pck_platform_crl.is_signature_valid(pck_platform_ca_pk)
    if pck_platform_crl.get_revoked_certificate_by_serial_number(
        pck_platform_ca_cert.serial_number
    ):
        logging.info(
            "[ %4s ] Checking Intel PCK Platform certificate against CRL", "FAIL"
        )
        raise CertificateRevokedError("Intel PCK Platform certificate revoked")

    logging.info(
        "[ %4s ] Checking certificates against Certificate Revocation List (CRL)", "OK"
    )

    try:
        # 1) Check Intel Root CA is self-signed
        root_ca_pk.verify(
            root_ca_cert.signature,
            root_ca_cert.tbs_certificate_bytes,
            ec.ECDSA(cast(HashAlgorithm, root_ca_cert.signature_hash_algorithm)),
        )
        # 2) Check Intel Root CA signed Intel PCK Platform CA
        root_ca_pk.verify(
            pck_platform_ca_cert.signature,
            pck_platform_ca_cert.tbs_certificate_bytes,
            ec.ECDSA(
                cast(HashAlgorithm, pck_platform_ca_cert.signature_hash_algorithm)
            ),
        )
        # 3) Check Intel PCK Platform CA signed Intel PCK certificate
        pck_platform_ca_pk.verify(
            pck_cert.signature,
            pck_cert.tbs_certificate_bytes,
            ec.ECDSA(cast(HashAlgorithm, pck_cert.signature_hash_algorithm)),
        )
    except cryptography.exceptions.InvalidSignature as exc:
        logging.info("[ %4s ] Certification chain verified", "FAIL")
        raise exc

    logging.info("[ %4s ] Certification chain verified", "OK")
