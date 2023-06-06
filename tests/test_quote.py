from cryptography import x509

from intel_sgx_ra.quote import Quote
from intel_sgx_ra.attest import verify_quote
from intel_sgx_ra.pck import sgx_pck_extension_from_cert, SgxPckExtension


def test_quote_parsing(data_path):
    raw_quote: bytes = (data_path / "quote.dat").read_bytes()
    quote: Quote = Quote.from_bytes(raw_quote)

    assert quote
    assert bytes(quote) == raw_quote
    assert quote.report_body.mr_signer == bytes.fromhex(
        "ac2c9fa87e4c91768b1d0c47169466c50d5a98c790639fbaefe7352a59919980")

    pck_cert, pck_platform_ca_cert, root_ca_cert, *others = [
        x509.load_pem_x509_certificate(raw_cert)
        for raw_cert in quote.certs()
    ]

    assert not others  # only 3 certificates


def test_quote_ra(data_path):
    raw_quote: bytes = (data_path / "quote.dat").read_bytes()
    quote: Quote = Quote.from_bytes(raw_quote)

    verify_quote(quote, pccs_url="https://pccs.mse.cosmian.com")


def test_pck_extension(data_path):
    raw_pck_cert: bytes = (data_path / "pck_cert.pem").read_bytes()
    pck_cert: x509.Certificate = x509.load_pem_x509_certificate(raw_pck_cert)

    pck_extension: SgxPckExtension = sgx_pck_extension_from_cert(pck_cert)

    assert "fmspc" in pck_extension
    assert isinstance(pck_extension["fmspc"], bytes)
    assert len(pck_extension["fmspc"]) == 6
