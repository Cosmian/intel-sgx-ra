"""intel_sgx_ra.cli.tools module."""

import argparse
import logging
import sys
from pathlib import Path

from intel_sgx_ra.error import CommandNotFound
from intel_sgx_ra.quote import Quote
from intel_sgx_ra.ratls import get_quote_from_cert, get_server_certificate, url_parse


def parse_args() -> argparse.Namespace:
    """CLI argument parser."""
    parser = argparse.ArgumentParser(description="Intel SGX DCAP Quote tools")
    parser.add_argument("--verbose", action="store_true", help="Verbose mode")

    subparsers = parser.add_subparsers(help="sub-command help", dest="command")

    cert_parser = subparsers.add_parser(
        "extract", help="Extract Quote from X.509 certificate using RA-TLS"
    )
    cert_parser.add_argument("OUTPUT", type=Path, help="Output filepath to write Quote")
    group = cert_parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--path", type=Path, help="Path to X.509 certificate used for RA-TLS"
    )
    group.add_argument(
        "--url", type=str, help="HTTPS URL to fetch X.509 certificate used for RA-TLS"
    )

    return parser.parse_args()


# pylint: disable=too-many-branches
def run() -> None:
    """Entrypoint of the CLI."""
    logging.basicConfig(format="%(message)s", level=logging.INFO)
    args = parse_args()

    quote: Quote

    if args.path:
        quote = get_quote_from_cert(args.path.read_bytes())
    elif args.url:
        host, port = url_parse(args.url)  # type: str, int

        quote = get_quote_from_cert(
            get_server_certificate((host, port)).encode("utf-8")
        )
    else:
        raise CommandNotFound("Bad args to subcommand!")

    args.OUTPUT.write_bytes(bytes(quote))

    sys.exit(0)
