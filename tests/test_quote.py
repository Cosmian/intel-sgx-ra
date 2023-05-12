from cryptography import x509

from intel_sgx_ra.quote import Quote
from intel_sgx_ra.attest import verify_quote


def test_quote_parsing(data_path):
    raw_quote: bytes = (data_path / "quote.dat").read_bytes()
    quote: Quote = Quote.from_bytes(raw_quote)

    assert quote
    assert bytes(quote) == raw_quote
    assert quote.report_body.mr_signer == bytes.fromhex(
        "c1c161d0dd996e8a9847de67ea2c00226761f7715a2c422d3012ac10795a1ef5")

    pck_cert, pck_platform_ca_cert, root_ca_cert, *others = [
        x509.load_pem_x509_certificate(raw_cert)
        for raw_cert in quote.certs()
    ]

    assert not others  # only 3 certificates


def test_quote_ra(data_path):
    raw_quote: bytes = (data_path / "quote.dat").read_bytes()
    quote: Quote = Quote.from_bytes(raw_quote)

    verify_quote(quote, pccs_url="https://pccs.mse.cosmian.com")
