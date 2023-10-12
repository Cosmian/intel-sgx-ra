"""intel_sgx_ra.pck module."""

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

# pylint: disable=no-name-in-module,import-error
from intel_sgx_ra.lib_sgx_dcap_ratls import SgxPckExtension, sgx_pck_extension_from_pem


def sgx_pck_extension_from_cert(cert: x509.Certificate) -> SgxPckExtension:
    """Parse Intel SGX PCK ASN.1 extension."""
    return sgx_pck_extension_from_pem(cert.public_bytes(encoding=Encoding.PEM))
