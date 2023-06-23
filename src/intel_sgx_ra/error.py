"""intel_sgx_ra.error module."""


class SGXQuoteNotFound(Exception):
    """SGX Quote extension not found in X509 certificate."""


class SGXVerificationError(Exception):
    """Error occured while verifying properties of SGX enclave."""


class RATLSVerificationError(Exception):
    """Certificate's public key different from report_data in SGX quote."""


class SGXDebugModeError(Exception):
    """SGX enclave is in debug mode."""


class CertificateRevokedError(Exception):
    """Certificate has been revoked."""


class PCCSResponseError(Exception):
    """Intel PCCS API reponse error."""


class MAAServiceError(Exception):
    """Microsoft Azure Attestation Service error."""


class CommandNotFound(Exception):
    """CLI command error."""


class CryptoKeyError(Exception):
    """Cryptographic key error."""


class CertificateError(Exception):
    """Server certificate error."""


class CollateralsError(Exception):
    """Collaterals are missing to verify quote."""
