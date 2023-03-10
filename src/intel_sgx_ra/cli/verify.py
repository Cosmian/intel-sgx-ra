"""intel_sgx_ra.cli.verify module."""

import argparse
import logging
import os
import sys
import traceback
from pathlib import Path
from pprint import pformat

from intel_sgx_ra.attest import remote_attestation
from intel_sgx_ra.error import (
    CertificateRevokedError,
    CommandNotFound,
    RATLSVerificationError,
    SGXDebugModeError,
    SGXQuoteNotFound,
)
from intel_sgx_ra.quote import Quote
from intel_sgx_ra.ratls import ratls_verification, ratls_verification_from_url

BASE_URL: str = os.getenv("PCCS_URL", "https://pccs.mse.cosmian.com")


def parse_args() -> argparse.Namespace:
    """CLI argument parser."""
    parser = argparse.ArgumentParser(description="Intel SGX DCAP Quote verification")
    parser.add_argument("--verbose", action="store_true", help="Verbose mode")
    parser.add_argument(
        "--mrenclave", type=str, help="Expected MRENCLAVE value in SGX quote"
    )
    parser.add_argument(
        "--mrsigner", type=str, help="Expected MRSIGNER value in SGX quote"
    )

    subparsers = parser.add_subparsers(help="sub-command help", dest="command")

    cert_parser = subparsers.add_parser(
        "certificate", help="Remote Attestation from X.509 certificate used for RA-TLS"
    )
    group = cert_parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--path", type=Path, help="Path to X.509 certificate used for RA-TLS"
    )
    group.add_argument(
        "--url", type=str, help="HTTPS URL to fetch X.509 certificate used for RA-TLS"
    )

    quote_parser = subparsers.add_parser(
        "quote", help="Remote Attestation of a raw SGX quote"
    )
    quote_parser.add_argument("path", type=Path, help="Path to raw quote")

    return parser.parse_args()


# pylint: disable=too-many-branches
def run() -> None:
    """Entrypoint of the CLI."""
    logging.basicConfig(format="%(message)s", level=logging.INFO)
    args = parse_args()

    quote: Quote

    if args.command == "certificate":
        quote = (
            ratls_verification(args.path.read_bytes())
            if args.path
            else ratls_verification_from_url(args.url)
        )
    elif args.command == "quote":
        quote = Quote.from_bytes(args.path.resolve().read_bytes())
    else:
        raise CommandNotFound("Bad subcommand!")

    try:
        remote_attestation(quote=quote, base_url=BASE_URL)
    except SGXQuoteNotFound:
        traceback.print_exc()
        sys.exit(1)
    except RATLSVerificationError:
        traceback.print_exc()
        sys.exit(2)
    except SGXDebugModeError:
        traceback.print_exc()
        sys.exit(3)
    except CertificateRevokedError:
        traceback.print_exc()
        sys.exit(4)

    if args.mrenclave:
        if quote.report_body.mr_enclave == bytes.fromhex(args.mrenclave):
            logging.info("[   OK ] MRENCLAVE matches expected value")
        else:
            logging.info("[ FAIL ] MRENCLAVE matches expected value")
            sys.exit(5)

    if args.mrsigner:
        if quote.report_body.mr_signer == bytes.fromhex(args.mrsigner):
            logging.info("[   OK ] MRSIGNER matches expected value")
        else:
            logging.info("[ FAIL ] MRSIGNER matches expected value")
            sys.exit(6)

    if args.verbose:
        logging.info(pformat(quote.to_dict()))

    sys.exit(0)
