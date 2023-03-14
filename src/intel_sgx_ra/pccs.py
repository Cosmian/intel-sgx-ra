"""intel_sgx_ra.pcs module."""

import re
from typing import Any, Dict, Literal, Optional, Tuple
from urllib.parse import unquote

import requests
from cryptography.x509 import (
    Certificate,
    CertificateRevocationList,
    load_der_x509_crl,
    load_pem_x509_certificate,
)

from intel_sgx_ra.error import PCCSResponseError
from intel_sgx_ra.quote import RE_CERT


def get_crl_by_uri(base_url: str, uri: str) -> bytes:
    """Retrieve CRL by URI."""
    response = requests.get(
        url=f"{base_url}/sgx/certification/v3/crl", json={"uri": uri}, timeout=30
    )

    return response.content


def get_root_ca_crl(base_url: str) -> CertificateRevocationList:
    """Retrieve Root CA CRL."""
    response = requests.get(
        url=f"{base_url}/sgx/certification/v3/rootcacrl", timeout=30
    )

    return load_der_x509_crl(bytes.fromhex(response.text))


def get_pck_certificate(
    base_url: str,
    encrypted_ppid: Optional[str],
    cpusvn: str,
    pcesvn: str,
    pceid: str,
    qeid: str,
) -> str:
    """Retrieve PCK Certificate from parameters."""
    response = requests.get(
        url=f"{base_url}/sgx/certification/v3/pckcert",
        params={
            "encrypted_ppid": encrypted_ppid,
            "cpusvn": cpusvn,
            "pcesvn": pcesvn,
            "pceid": pceid,
            "qeid": qeid,
        },
        timeout=30,
    )

    pck_cert = response.text

    return pck_cert


def get_pck_cert_crl(
    base_url: str, ca: Literal["processor", "platform"]
) -> CertificateRevocationList:
    """Retrieve PCK CRL."""
    response = requests.get(
        url=f"{base_url}/sgx/certification/v3/pckcrl",
        params={"ca": ca, "encoding": "der"},
        timeout=30,
    )

    return load_der_x509_crl(response.content)


def get_tcbinfo(
    base_url: str, fmscp: str
) -> Tuple[Tuple[Certificate, Certificate], Dict[str, Any]]:
    """Retrieve TCB info from `fmscp`."""
    response = requests.get(
        url=f"{base_url}/sgx/certification/v3/tcb", params={"fmspc": fmscp}, timeout=30
    )
    cert_chain = unquote(response.headers["SGX-TCB-Info-Issuer-Chain"])
    tcb_cert, root_ca_cert, *others = [
        load_pem_x509_certificate(raw_cert)
        for raw_cert in re.findall(RE_CERT, cert_chain.encode("utf-8"))
    ]

    if others:
        raise PCCSResponseError(
            "More than 2 certifices in header SGX-TCB-Info-Issuer-Chain"
        )

    return (tcb_cert, root_ca_cert), response.json()


def get_qe_identity(
    base_url: str,
) -> Tuple[Tuple[Certificate, Certificate], Dict[str, Any]]:
    """Retrieve Quoting Enclave Identity."""
    response = requests.get(
        url=f"{base_url}/sgx/certification/v3/qe/identity", timeout=30
    )

    cert_chain = unquote(response.headers["SGX-Enclave-Identity-Issuer-Chain"])
    tcb_cert, root_ca_cert, *others = [
        load_pem_x509_certificate(raw_cert)
        for raw_cert in re.findall(RE_CERT, cert_chain.encode("utf-8"))
    ]
    if others:
        raise PCCSResponseError(
            "More than 2 certifices in header SGX-Enclave-Identity-Issuer-Chain"
        )

    return (tcb_cert, root_ca_cert), response.json()


def get_qve_identity(
    base_url: str,
) -> Tuple[Tuple[Certificate, Certificate], Dict[str, Any]]:
    """Retrieve Quoting Verification Enclave Identity."""
    response = requests.get(
        url=f"{base_url}/sgx/certification/v3/qve/identity", timeout=30
    )

    cert_chain = unquote(response.headers["SGX-Enclave-Identity-Issuer-Chain"])
    tcb_cert, root_ca_cert, *others = [
        load_pem_x509_certificate(raw_cert)
        for raw_cert in re.findall(RE_CERT, cert_chain.encode("utf-8"))
    ]
    if others:
        raise PCCSResponseError(
            "More than 2 certifices in header SGX-Enclave-Identity-Issuer-Chain"
        )

    return (tcb_cert, root_ca_cert), response.json()
