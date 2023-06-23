"""intel_sgx_ra.maa.attest module."""

from typing import Any, Dict, Optional, Union, cast

import requests
from authlib.jose import JsonWebSignature
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from intel_sgx_ra.base64url import base64url_decode, base64url_encode
from intel_sgx_ra.error import MAAServiceError
from intel_sgx_ra.quote import Quote


def maa_attest(quote: bytes, enclave_held_data: Optional[bytes]) -> Dict[str, Any]:
    """Attest SGX enclave request to Microsoft Azure Attestation (MAA) service API.

    Parameters
    ----------
    quote : bytes
        Intel SGX quote.
    enclave_held_data : Optional[bytes]
        Expected data in the report data section of Intel SGX quote.

    Returns
    -------
    Dict[str, Any]
        JSON decoded with 'token' key containing a RS256 JWT.

    """
    payload: Dict[str, Any] = {"quote": base64url_encode(quote)}

    if enclave_held_data is not None:
        # Runtime data are generated by the Trusted Execution Environment (TEE). For an
        # SGX quote, the SHA256 hash of the RuntimeData must match the lower 32 bytes of
        # the quote's "report data" attribute.
        payload["runtimeData"] = {
            "data": base64url_encode(enclave_held_data),
            "dataType": "Binary",
        }

    response = requests.post(
        url="https://sharedneu.neu.attest.azure.net/attest/SgxEnclave",
        params={"api-version": "2022-08-01"},
        json=payload,
        timeout=30,
    )

    response.raise_for_status()

    return response.json()


def maa_certificates() -> Dict[str, Any]:
    """Retrieve Microsoft certificates for Azure remote attestation.

    Returns
    -------
    Dict[str, Any]
        JSON Web Key (JWK) set deserialized containing Microsoft certificates.

    """
    response = requests.get(
        url="https://sharedneu.neu.attest.azure.net/certs", timeout=30
    )

    return response.json()


def verify_jws(token: str, jwks: Dict[str, Any]) -> Dict[str, Any]:
    """Check signature of JWT `token` using JSWK set.

    Parameters
    ----------
    token : str
        JSON Web Token (JWT) which contains a RS256 JSON Web Signature (JWS).
    jwks : Dict[str, Any]
        JSON Web Key (JWK) set with certificates.

    Returns
    -------
    Dict[str, Any]
        Payload of the RS256 JWT if signature is verified.

    """
    jws = JsonWebSignature(algorithms=["RS256"])

    def load_key_from_jwks(header, _payload):
        kid = header["kid"]
        for jwk in jwks["keys"]:
            if jwk["kid"] == kid:
                x5c, *_ = jwk["x5c"]
                if jwk["kty"] != "RSA":
                    raise MAAServiceError("kid found but not an RSA public key")
                cert: x509.Certificate = x509.load_der_x509_certificate(
                    base64url_decode(x5c)
                )
                return cert.public_key().public_bytes(Encoding.PEM, PublicFormat.PKCS1)
        raise MAAServiceError(f"kid '{kid}' not found")

    return jws.deserialize(s=token, key=load_key_from_jwks)


def verify_quote(
    quote: Union[Quote, bytes], enclave_held_data: Optional[bytes] = None
) -> Dict[str, Any]:
    """Azure remote attestation with Microsoft Azure Attestation (MAA) service.

    Parameters
    ----------
    quote : Union[Quote, bytes]
        Intel SGX quote.
    enclave_held_data : Optional[bytes]
        Data in the user report data section of the Intel's quote.

    Returns
    -------
    Dict[str, Any]
        JSON response of the MAA service API.

    """
    quote = cast(Quote, Quote.from_bytes(quote) if isinstance(quote, bytes) else quote)

    token: str = maa_attest(bytes(quote), enclave_held_data)["token"]
    jwks: Dict[str, Any] = maa_certificates()

    return verify_jws(token, jwks)
