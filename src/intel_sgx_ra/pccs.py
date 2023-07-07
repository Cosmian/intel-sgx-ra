"""intel_sgx_ra.pcs module."""

import re
from http import HTTPStatus
from typing import Literal, Tuple
from urllib.parse import unquote

import requests
from cryptography import x509

from intel_sgx_ra.error import PCCSResponseError
from intel_sgx_ra.quote import RE_CERT


def get_root_ca_crl(pccs_url: str) -> x509.CertificateRevocationList:
    """Retrieve Root CA CRL.

    Parameters
    ----------
    pccs_url : str
        URL of the PCCS.

    Returns
    -------
    x509.CertificateRevocationList
        Intel SGX Root CA CRL.

    """
    response: requests.Response = requests.get(
        url=f"{pccs_url}/sgx/certification/v4/rootcacrl", timeout=30
    )

    if response.status_code == HTTPStatus.NOT_FOUND:
        raise PCCSResponseError("Root CA CRL cannot be found")
    if response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
        raise PCCSResponseError("Internal server error occurred")
    if response.status_code == HTTPStatus.BAD_GATEWAY:
        raise PCCSResponseError(
            "Unable to retrieve the collateral from the Intel SGX PCS"
        )
    if response.status_code != HTTPStatus.OK:
        raise PCCSResponseError(f"Unknown error, status code {response.status_code}")

    return x509.load_der_x509_crl(bytes.fromhex(response.text))


def get_pck_cert_crl(
    pccs_url: str, ca: Literal["processor", "platform"]
) -> Tuple[x509.Certificate, x509.Certificate, x509.CertificateRevocationList]:
    """Retrieve the CRL of revoked Intel SGX PCK Certificates.

    The Certificate Revocation List is issued either by Intel SGX Platform
    CA or by Intel SGX Processor CA.

    Parameters
    ----------
    pccs_url : str
        URL of the PCCS.
    ca : Literal["processor", "platform"]
        Identifier of the CA that issued the requested CRL.

    Returns
    -------
    Tuple[x509.Certificate, x509.Certificate, x509.CertificateRevocationList]
        Intel SGX Root CA certificate, Intel SGX Platform or Processor CA certificate
        and Intel SGX Platform or Processor CA CRL.

    """
    response: requests.Response = requests.get(
        url=f"{pccs_url}/sgx/certification/v4/pckcrl",
        params={"ca": ca, "encoding": "der"},
        timeout=30,
    )

    if response.status_code == HTTPStatus.BAD_REQUEST:
        raise PCCSResponseError("Invalid request parameters")
    if response.status_code == HTTPStatus.NOT_FOUND:
        raise PCCSResponseError("PCK CRL cannot be found")
    if response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
        raise PCCSResponseError("Internal server error occurred")
    if response.status_code == HTTPStatus.BAD_GATEWAY:
        raise PCCSResponseError(
            "Unable to retrieve the collateral from the Intel SGX PCS"
        )
    if response.status_code != HTTPStatus.OK:
        raise PCCSResponseError(f"Unknown error, status code {response.status_code}")

    pck_ca_cert, root_ca_cert, *others = [
        x509.load_pem_x509_certificate(raw_cert)
        for raw_cert in re.findall(
            RE_CERT,
            unquote(response.headers["sgx-pck-crl-issuer-chain"]).encode("ascii"),
        )
    ]
    if others:
        raise PCCSResponseError(
            "More than 2 certificates in header sgx-pck-certificate-issuer-chain"
        )

    return root_ca_cert, pck_ca_cert, x509.load_der_x509_crl(response.content)


def get_tcbinfo(
    pccs_url: str, fmscp: bytes
) -> Tuple[bytes, x509.Certificate, x509.Certificate]:
    """Retrieve SGX TCB information for given FMSPC.

    Parameters
    ----------
    pccs_url : str
        URL of the PCCS.
    fmscp : bytes
        Base16-encoded FMSPC value (6 bytes).

    Returns
    -------
    Tuple[bytes, x509.Certificate, x509.Certificate]
        Bytes of the JSON containing TcbInfoV3 (see [1]), Intel SGX Root CA
        certificate and Intel SGX TCB signing certificate.

    References
    ----------
    .. [1] https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-model-v3

    """  # noqa: E501 # pylint: disable=line-too-long
    response = requests.get(
        url=f"{pccs_url}/sgx/certification/v4/tcb",
        params={"fmspc": fmscp.hex()},
        timeout=30,
    )

    tcb_cert, root_ca_cert, *others = [
        x509.load_pem_x509_certificate(raw_cert)
        for raw_cert in re.findall(
            RE_CERT, unquote(response.headers["TCB-Info-Issuer-Chain"]).encode("ascii")
        )
    ]

    if others:
        raise PCCSResponseError(
            "More than 2 certificates in header TCB-Info-Issuer-Chain"
        )

    return response.content, root_ca_cert, tcb_cert


def get_qe_identity(
    pccs_url: str,
) -> Tuple[bytes, x509.Certificate, x509.Certificate]:
    """Retrieve Quoting Enclave Identity.

    Parameters
    ----------
    pccs_url : str
        URL of the PCCS.

    Returns
    -------
    Tuple[bytes, x509.Certificate, x509.Certificate]
        Bytes of the JSON containing QEIdentityV2 (see [1]), Intel SGX Root CA
        certificate and Intel SGX TCB signing certificate.

    References
    ----------
    .. [1] https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-model-v2.

    """  # noqa: E501 # pylint: disable=line-too-long
    response = requests.get(
        url=f"{pccs_url}/sgx/certification/v4/qe/identity", timeout=30
    )

    tcb_cert, root_ca_cert, *others = [
        x509.load_pem_x509_certificate(raw_cert)
        for raw_cert in re.findall(
            RE_CERT,
            unquote(response.headers["SGX-Enclave-Identity-Issuer-Chain"]).encode(
                "ascii"
            ),
        )
    ]
    if others:
        raise PCCSResponseError(
            "More than 2 certifices in header SGX-Enclave-Identity-Issuer-Chain"
        )

    return response.content, root_ca_cert, tcb_cert
