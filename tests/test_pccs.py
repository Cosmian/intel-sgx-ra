from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from intel_sgx_ra.quote import Quote
from intel_sgx_ra.pccs import get_root_ca_crl, get_pck_cert_crl, get_qe_identity


def test_root_ca(data_path, pccs_url):
    quote: Quote = Quote.from_bytes((data_path / "quote.dat").read_bytes())
    now = datetime.now(timezone.utc)

    _, _, root_ca_cert = [
        x509.load_pem_x509_certificate(raw_cert)
        for raw_cert in quote.certs()
    ]
    root_ca_cert.verify_directly_issued_by(root_ca_cert)
    assert root_ca_cert.public_key().verify(
        root_ca_cert.signature,
        root_ca_cert.tbs_certificate_bytes,
        ec.ECDSA(root_ca_cert.signature_hash_algorithm),
    ) is None
    assert root_ca_cert.not_valid_before_utc <= now <= root_ca_cert.not_valid_after_utc

    # TODO: add new data this test
    # root_ca_crl = get_root_ca_crl(pccs_url)
    #
    # assert root_ca_crl.is_signature_valid(root_ca_cert.public_key())
    # assert root_ca_crl.get_revoked_certificate_by_serial_number(root_ca_cert.serial_number) is None


def test_pck_ca(data_path, pccs_url):
    quote: Quote = Quote.from_bytes((data_path / "quote.dat").read_bytes())
    now = datetime.now(timezone.utc)

    _, pck_ca_cert, root_ca_cert = [
        x509.load_pem_x509_certificate(raw_cert)
        for raw_cert in quote.certs()
    ]
    root_ca_cert.verify_directly_issued_by(root_ca_cert)
    pck_ca_cert.verify_directly_issued_by(root_ca_cert)
    assert root_ca_cert.public_key().verify(
        pck_ca_cert.signature,
        pck_ca_cert.tbs_certificate_bytes,
        ec.ECDSA(pck_ca_cert.signature_hash_algorithm),
    ) is None
    assert pck_ca_cert.not_valid_before_utc <= now <= pck_ca_cert.not_valid_after_utc

    common_name, *_ = pck_ca_cert.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME
    )
    assert common_name.value == "Intel SGX PCK Platform CA"

    # TODO: add new data this test
    # _root_ca_cert, _pck_ca_cert, pck_ca_crl = get_pck_cert_crl(pccs_url, "platform")
    #
    # assert _root_ca_cert == root_ca_cert
    # assert _pck_ca_cert == pck_ca_cert
    # assert pck_ca_crl.is_signature_valid(pck_ca_cert.public_key())
    # assert pck_ca_crl.get_revoked_certificate_by_serial_number(pck_ca_cert.serial_number) is None


def test_pck(data_path, pccs_url):
    quote: Quote = Quote.from_bytes((data_path / "quote.dat").read_bytes())
    now = datetime.now(timezone.utc)

    pck_cert, pck_ca_cert, root_ca_cert = [
        x509.load_pem_x509_certificate(raw_cert)
        for raw_cert in quote.certs()
    ]
    root_ca_cert.verify_directly_issued_by(root_ca_cert)
    pck_ca_cert.verify_directly_issued_by(root_ca_cert)
    pck_cert.verify_directly_issued_by(pck_ca_cert)
    assert pck_ca_cert.public_key().verify(
        pck_cert.signature,
        pck_cert.tbs_certificate_bytes,
        ec.ECDSA(pck_cert.signature_hash_algorithm),
    ) is None
    assert pck_cert.not_valid_before_utc <= now <= pck_cert.not_valid_after_utc

    # TODO: add new data this test
    # tcb_info, _root_ca_cert, tcb_cert = get_qe_identity(pccs_url)
    # assert _root_ca_cert == root_ca_cert
    # assert tcb_cert.not_valid_before_utc <= now <= tcb_cert.not_valid_after_utc
