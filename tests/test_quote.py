import re
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from intel_sgx_ra.quote import Quote, RE_CERT


def test_quote_parsing(data_path):
    raw_quote: bytes = (data_path / "quote.dat").read_bytes()
    quote: Quote = Quote.from_bytes(raw_quote)

    assert quote
    assert bytes(quote) == raw_quote
    assert quote.report_body.mr_signer == bytes.fromhex(
        "c1c161d0dd996e8a9847de67ea2c00226761f7715a2c422d3012ac10795a1ef5")

    raw_certs: List[bytes] = re.findall(RE_CERT, quote.signature)
    pck_cert, pck_platform_ca_cert, root_ca_cert, *others = [
        x509.load_pem_x509_certificate(raw_cert)
        for raw_cert in raw_certs
    ]

    assert not others  # only 3 certificates

    # 1) Check Intel Root CA self-signature
    root_ca_cert.public_key().verify(
        root_ca_cert.signature,
        root_ca_cert.tbs_certificate_bytes,
        ec.ECDSA(root_ca_cert.signature_hash_algorithm)
    )
    # 2) Check Intel PCK Platform CA signature by Intel Root CA
    root_ca_cert.public_key().verify(
        pck_platform_ca_cert.signature,
        pck_platform_ca_cert.tbs_certificate_bytes,
        ec.ECDSA(pck_platform_ca_cert.signature_hash_algorithm)
    )
    # 3) Check Intel PCK certificate signature by Intel PCK Platform CA
    pck_platform_ca_cert.public_key().verify(
        pck_cert.signature,
        pck_cert.tbs_certificate_bytes,
        ec.ECDSA(pck_cert.signature_hash_algorithm)
    )
