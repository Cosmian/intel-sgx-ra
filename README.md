# Intel SGX DCAP Remote Attestation library

## Overview

Python library for Intel SGX DCAP remote attestation.

## Installation

```console
$ pip install intel-sgx-ra
```

## Usage

```console
$ sgx-ra-verify --help
usage: sgx-ra-verify [-h] [--verbose] [--mrenclave MRENCLAVE] [--mrsigner MRSIGNER] {certificate,quote} ...

Intel SGX DCAP Quote verification

positional arguments:
  {certificate,quote}   sub-command help
    certificate         Remote Attestation from X.509 certificate used for RA-TLS
    quote               Remote Attestation of a raw SGX quote

optional arguments:
  -h, --help            show this help message and exit
  --verbose             Verbose mode
  --mrenclave MRENCLAVE
                        Expected MRENCLAVE value in SGX quote
  --mrsigner MRSIGNER   Expected MRSIGNER value in SGX quote
$ sgx-ra-utils --help
usage: sgx-ra-utils [-h] [--verbose] {extract} ...

Intel SGX DCAP Quote tools

positional arguments:
  {extract}   sub-command help
    extract   Extract Quote from X.509 certificate using RA-TLS

optional arguments:
  -h, --help  show this help message and exit
  --verbose   Verbose mode
```
