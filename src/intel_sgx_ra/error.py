"""intel_sgx_ra.error module."""


class SGXQuoteNotFound(Exception):
    """SGX Quote extension not found in X509 certificate."""


class RATLSVerificationError(Exception):
    """Cert public key different from report_data in SGX quote."""


class SGXDebugModeError(Exception):
    """SGX enclave is in debug mode."""


class CertificateRevokedError(Exception):
    """Intel Root CA revoked."""


class PCCSResponseError(Exception):
    """Intel PCCS API reponse error."""


class CommandNotFound(Exception):
    """CLI command error."""


class CryptoKeyError(Exception):
    """Cryptographic key error."""
