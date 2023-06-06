"""intel_ra_sgx.attest module."""

import json
import logging
from datetime import datetime
from hashlib import sha256
from typing import Any, Dict, Literal, Optional, Tuple, Union, cast

import cryptography.exceptions
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm

from intel_sgx_ra import globs
from intel_sgx_ra.error import (
    CertificateError,
    CertificateRevokedError,
    CollateralsError,
    SGXDebugModeError,
    SGXVerificationError,
)
from intel_sgx_ra.pccs import get_pck_cert_crl, get_root_ca_crl, get_tcbinfo
from intel_sgx_ra.pck import SgxPckExtension, sgx_pck_extension_from_cert
from intel_sgx_ra.quote import Quote

# define SGX_FLAGS_DEBUG 0x0000000000000002ULL
SGX_FLAGS_DEBUG: int = 2


def verify_pck_chain(
    root_ca_cert: x509.Certificate,
    pck_ca_cert: x509.Certificate,
    pck_cert: x509.Certificate,
    root_ca_crl: x509.CertificateRevocationList,
    pck_ca_crl: x509.CertificateRevocationList,
) -> bool:
    """PCK certification chain validation."""
    now: datetime = datetime.utcnow()

    pck_ca_pk, root_ca_pk = (
        cast(ec.EllipticCurvePublicKey, pck_ca_cert.public_key()),
        cast(ec.EllipticCurvePublicKey, root_ca_cert.public_key()),
    )

    # Check issuers
    root_ca_cert.verify_directly_issued_by(root_ca_cert)
    pck_ca_cert.verify_directly_issued_by(root_ca_cert)
    pck_cert.verify_directly_issued_by(pck_ca_cert)

    # Check expiration date of certificates
    if not root_ca_cert.not_valid_before <= now <= root_ca_cert.not_valid_after:
        raise CertificateError("Intel Root CA certificate has expired")
    if not pck_ca_cert.not_valid_before <= now <= pck_ca_cert.not_valid_after:
        raise CertificateError("Intel PCK CA certificate has expired")
    if not pck_cert.not_valid_before <= now <= pck_cert.not_valid_after:
        raise CertificateError("Intel PCK certificate has expired")

    # Check Intel Root CA signed Intel Root CA CRL and not revoked
    if not root_ca_crl.is_signature_valid(root_ca_pk):
        raise CertificateError("Invalid Intel Root CA CRL signature")

    if root_ca_crl.get_revoked_certificate_by_serial_number(root_ca_cert.serial_number):
        logging.info("%s Check Intel Root CA certificate against CRL", globs.FAIL)
        raise CertificateRevokedError("Intel Root CA certificate revoked")

    # Check Intel PCK Platform/Processor signed Intel PCK CRL and not revoked
    if not pck_ca_crl.is_signature_valid(pck_ca_pk):
        raise CertificateError("Invalid Intel PCK CA CRL signature")

    if pck_ca_crl.get_revoked_certificate_by_serial_number(pck_ca_cert.serial_number):
        logging.info("%s Check Intel PCK CA certificate against CRL", globs.FAIL)
        raise CertificateRevokedError("Intel PCK CA certificate revoked")

    try:
        # 1) Check Intel Root CA is self-signed
        root_ca_pk.verify(
            root_ca_cert.signature,
            root_ca_cert.tbs_certificate_bytes,
            ec.ECDSA(cast(HashAlgorithm, root_ca_cert.signature_hash_algorithm)),
        )
        # 2) Check Intel Root CA signed Intel PCK Platform/Processor CA
        root_ca_pk.verify(
            pck_ca_cert.signature,
            pck_ca_cert.tbs_certificate_bytes,
            ec.ECDSA(cast(HashAlgorithm, pck_ca_cert.signature_hash_algorithm)),
        )
        # 3) Check Intel PCK Platform/Processor CA signed Intel PCK certificate
        pck_ca_pk.verify(
            pck_cert.signature,
            pck_cert.tbs_certificate_bytes,
            ec.ECDSA(cast(HashAlgorithm, pck_cert.signature_hash_algorithm)),
        )
    except cryptography.exceptions.InvalidSignature as exc:
        logging.info("%s Certification chain", globs.FAIL)
        raise exc

    logging.info("%s Certification chain", globs.OK)

    return True


def verify_tcb(
    tcb_info: bytes, tcb_cert: x509.Certificate, root_ca_cert: x509.Certificate
) -> bool:
    """Verify TCB information."""
    now: datetime = datetime.utcnow()

    tcb: Dict[str, Any] = json.loads(tcb_info)

    assert tcb["tcbInfo"]["version"] == 3
    assert tcb["tcbInfo"]["id"] == "SGX"
    assert now < datetime.strptime(tcb["tcbInfo"]["nextUpdate"], "%Y-%m-%dT%H:%M:%SZ")

    root_ca_pk = cast(ec.EllipticCurvePublicKey, root_ca_cert.public_key())

    # Check issuers
    root_ca_cert.verify_directly_issued_by(root_ca_cert)
    tcb_cert.verify_directly_issued_by(root_ca_cert)

    # Check expiration date of certificates
    if not root_ca_cert.not_valid_before <= now <= root_ca_cert.not_valid_after:
        raise CertificateError("Intel Root CA certificate has expired")
    if not tcb_cert.not_valid_before <= now <= tcb_cert.not_valid_after:
        raise CertificateError("Intel TCB certificate has expired")

    try:
        # 1) Check Intel Root CA is self-signed
        root_ca_pk.verify(
            root_ca_cert.signature,
            root_ca_cert.tbs_certificate_bytes,
            ec.ECDSA(cast(HashAlgorithm, root_ca_cert.signature_hash_algorithm)),
        )
        # 2) Check Intel Root CA signed Intel TCB certificate
        root_ca_pk.verify(
            tcb_cert.signature,
            tcb_cert.tbs_certificate_bytes,
            ec.ECDSA(cast(HashAlgorithm, tcb_cert.signature_hash_algorithm)),
        )
    except cryptography.exceptions.InvalidSignature as exc:
        logging.info("%s TCB verification", globs.FAIL)
        raise exc

    logging.info("%s TCB verification", globs.OK)

    return True


def retrieve_collaterals(
    quote: Quote,
    pccs_url: str,
) -> Tuple[
    bytes,
    x509.Certificate,
    x509.CertificateRevocationList,
    x509.CertificateRevocationList,
]:
    """Retrive collaterals from PCCS URL and PCK CA type."""
    pck_cert, pck_ca_cert, _root_ca_cert = [
        x509.load_pem_x509_certificate(raw_cert) for raw_cert in quote.certs()
    ]  # type: x509.Certificate, x509.Certificate, x509.Certificate

    sgx_pck_ext: SgxPckExtension = sgx_pck_extension_from_cert(pck_cert)
    fmspc: bytes = sgx_pck_ext["fmspc"]

    common_name: x509.NameAttribute
    common_name, *_ = pck_ca_cert.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME
    )
    ca: Literal["processor", "platform"]
    if common_name.value == "Intel SGX PCK Platform CA":
        ca = "platform"
    elif common_name.value == "Intel SGX PCK Processor CA":
        ca = "processor"
    else:
        raise CertificateError("Unknown CN in Intel SGX PCK Platform/Processor CA")

    root_ca_crl: x509.CertificateRevocationList = get_root_ca_crl(pccs_url)
    pck_ca_crl: x509.CertificateRevocationList = get_pck_cert_crl(pccs_url, ca)
    tcb_info, tcb_cert = get_tcbinfo(pccs_url, fmspc)

    return tcb_info, tcb_cert, root_ca_crl, pck_ca_crl


def verify_quote(
    quote: Union[Quote, bytes],
    collaterals: Optional[
        Tuple[
            bytes,
            x509.Certificate,
            x509.CertificateRevocationList,
            x509.CertificateRevocationList,
        ]
    ] = None,
    pccs_url: Optional[str] = None,
):
    """Process DCAP remote attestation with `quote`."""
    quote = cast(Quote, Quote.from_bytes(quote) if isinstance(quote, bytes) else quote)

    # If set, then the enclave is in debug mode
    debug: bool = bool(quote.report_body.flags & SGX_FLAGS_DEBUG)

    logging.info("%s No SGX debug mode", globs.FAIL if debug else globs.OK)

    if debug:
        raise SGXDebugModeError

    pck_cert, pck_ca_cert, root_ca_cert = [
        x509.load_pem_x509_certificate(raw_cert) for raw_cert in quote.certs()
    ]  # type: x509.Certificate, x509.Certificate, x509.Certificate

    tcb_info: bytes
    tcb_cert: x509.Certificate
    root_ca_crl: x509.CertificateRevocationList
    pck_ca_crl: x509.CertificateRevocationList
    if pccs_url is not None:
        tcb_info, tcb_cert, root_ca_crl, pck_ca_crl = retrieve_collaterals(
            quote, pccs_url
        )
    elif collaterals is not None:
        tcb_info, tcb_cert, root_ca_crl, pck_ca_crl = collaterals
    else:
        raise CollateralsError("Collaterals or PCCS URL missing")

    assert verify_pck_chain(
        root_ca_cert, pck_ca_cert, pck_cert, root_ca_crl, pck_ca_crl
    )
    assert verify_tcb(tcb_info, tcb_cert, root_ca_cert)

    ecdsa_attestation_pk = ec.EllipticCurvePublicNumbers(
        curve=ec.SECP256R1(),
        x=int.from_bytes(quote.auth_data.public_key[:32], byteorder="big"),
        y=int.from_bytes(quote.auth_data.public_key[32:], byteorder="big"),
    ).public_key()

    try:
        ecdsa_attestation_pk.verify(
            signature=encode_dss_signature(
                r=int.from_bytes(quote.auth_data.signature[:32], byteorder="big"),
                s=int.from_bytes(quote.auth_data.signature[32:], byteorder="big"),
            ),
            data=bytes(quote.header) + bytes(quote.report_body),
            signature_algorithm=ec.ECDSA(SHA256()),
        )
    except cryptography.exceptions.InvalidSignature as exc:
        logging.info("%s Quote signature", globs.FAIL)
        raise exc

    logging.info("%s Quote signature", globs.OK)

    try:
        pck_pk = cast(ec.EllipticCurvePublicKey, pck_cert.public_key())
        pck_pk.verify(
            signature=encode_dss_signature(
                r=int.from_bytes(
                    quote.auth_data.qe_report_signature[:32], byteorder="big"
                ),
                s=int.from_bytes(
                    quote.auth_data.qe_report_signature[32:], byteorder="big"
                ),
            ),
            data=bytes(quote.auth_data.qe_report),
            signature_algorithm=ec.ECDSA(SHA256()),
        )
    except cryptography.exceptions.InvalidSignature as exc:
        logging.info("%s QE report signature", globs.FAIL)
        raise exc

    expected_qe_report_data: bytes = sha256(
        quote.auth_data.public_key + quote.auth_data.qe_auth_data
    ).digest()

    if quote.auth_data.qe_report.report_data[:32] != expected_qe_report_data:
        raise SGXVerificationError("Unexpected REPORTDATA in QE report")

    logging.info("%s QE report signature", globs.OK)
