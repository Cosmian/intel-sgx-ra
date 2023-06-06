"""intel_sgx_ra.pck module."""

from enum import Enum
from typing import TypedDict, cast

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

# pylint: disable=no-name-in-module,import-error
from intel_sgx_ra.lib_sgx_dcap_ratls import sgx_pck_extension_from_pem


class SgxType(Enum):
    """Sub-structure SgxType."""

    Standard = 0
    Scalable = 1


class SgxPckExtension(TypedDict):
    """Struct SgxPckExtension."""

    ppid: bytes
    compsvn: bytes
    pcesvn: int
    cpusvn: bytes
    pceid: bytes
    fmspc: bytes
    sgx_type: SgxType
    platform_instance_id: bytes
    dynamic_platform: bool
    cached_keys: bool
    smt_enabled: bool


def sgx_pck_extension_from_cert(cert: x509.Certificate) -> SgxPckExtension:
    """Parse Intel SGX PCK ASN.1 extension."""
    return cast(
        SgxPckExtension,
        sgx_pck_extension_from_pem(cert.public_bytes(encoding=Encoding.PEM)),
    )
