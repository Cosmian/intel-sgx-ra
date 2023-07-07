"""intel_sgx_ra.cli.verify module."""

import argparse
import logging
import sys
import traceback
from pathlib import Path
from pprint import pformat

from intel_sgx_ra import globs
from intel_sgx_ra.attest import verify_quote
from intel_sgx_ra.error import (
    CertificateRevokedError,
    CommandNotFound,
    RATLSVerificationError,
    SGXDebugModeError,
    SGXQuoteNotFound,
)
from intel_sgx_ra.maa.attest import verify_quote as azure_verify_quote
from intel_sgx_ra.quote import Quote
from intel_sgx_ra.ratls import ratls_verify, ratls_verify_from_url


def parse_args() -> argparse.Namespace:
    """CLI argument parser."""
    parser = argparse.ArgumentParser(description="Intel SGX DCAP quote verification")
    parser.add_argument("--verbose", action="store_true", help="Verbose mode")
    parser.add_argument(
        "--mrenclave",
        metavar="HEXDIGEST",
        type=str,
        help="Expected MRENCLAVE value in SGX quote",
    )
    parser.add_argument(
        "--mrsigner",
        metavar="HEXDIGEST",
        type=str,
        help="Expected MRSIGNER value in SGX quote",
    )

    ra_type_group = parser.add_mutually_exclusive_group(required=True)
    ra_type_group.add_argument(
        "--pccs-url",
        metavar="URL",
        type=str,
        help="Provisioning Certificate Cache Service URL (Intel DCAP)",
    )
    ra_type_group.add_argument(
        "--azure-attestation",
        action="store_true",
        help="Microsoft Azure Attestation Service (Azure DCAP)",
    )

    subparsers = parser.add_subparsers(help="sub-command help", dest="command")

    cert_parser = subparsers.add_parser(
        "certificate", help="Remote Attestation from RA-TLS X.509 certificate"
    )
    cert_source_type = cert_parser.add_mutually_exclusive_group(required=True)
    cert_source_type.add_argument(
        "--path",
        metavar="FILE",
        type=Path,
        help="Path to RA-TLS X.509 certificate",
    )
    cert_source_type.add_argument(
        "--url",
        metavar="URL",
        type=str,
        help="HTTPS URL to fetch server's certificate",
    )

    quote_parser = subparsers.add_parser(
        "quote", help="Remote Attestation of a raw SGX quote"
    )
    quote_parser.add_argument("path", type=Path, help="Path to raw quote")

    return parser.parse_args()


# pylint: disable=too-many-branches
def run() -> None:
    """Entrypoint of the CLI."""
    args = parse_args()
    logging.basicConfig(
        format="%(message)s", level=logging.DEBUG if args.verbose else logging.INFO
    )

    quote: Quote

    if args.command == "certificate":
        quote = (
            ratls_verify(args.path.read_bytes())
            if args.path
            else ratls_verify_from_url(args.url)
        )
    elif args.command == "quote":
        quote = Quote.from_bytes(args.path.resolve().read_bytes())
    else:
        raise CommandNotFound("Bad subcommand!")

    try:
        if args.pccs_url:
            verify_quote(quote=quote, pccs_url=args.pccs_url)
        if args.azure_attestation:
            azure_verify_quote(quote)

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
            logging.info("%s MRENCLAVE matches expected value", globs.OK)
        else:
            logging.info("%s MRENCLAVE matches expected value", globs.FAIL)
            sys.exit(5)

    if args.mrsigner:
        if quote.report_body.mr_signer == bytes.fromhex(args.mrsigner):
            logging.info("%s MRSIGNER matches expected value", globs.OK)
        else:
            logging.info("%s MRSIGNER matches expected value", globs.FAIL)
            sys.exit(6)

    logging.debug(pformat(quote.to_dict()))

    sys.exit(0)
