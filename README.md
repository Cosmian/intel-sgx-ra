# Intel SGX Remote Attestation library

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
    certificate         Remote Attestation for ra-tls X.509 certificate
    quote               Remote Attestation of a raw SGX quote

optional arguments:
  -h, --help            show this help message and exit
  --verbose             Verbose mode
  --mrenclave MRENCLAVE
                        Expected MRENCLAVE value in SGX quote
  --mrsigner MRSIGNER   Expected MRSIGNER value in SGX quote
```
