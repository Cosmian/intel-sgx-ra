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
usage: sgx-ra-verify [-h] [--verbose] [--mrenclave HEXDIGEST]
                     [--mrsigner HEXDIGEST]
                     (--pccs-url URL | --azure-attestation)
                     {certificate,quote} ...

Intel SGX DCAP quote verification

positional arguments:
  {certificate,quote}   sub-command help
    certificate         Remote Attestation from RA-TLS X.509 certificate
    quote               Remote Attestation of a raw SGX quote

optional arguments:
  -h, --help            show this help message and exit
  --verbose             Verbose mode
  --mrenclave HEXDIGEST
                        Expected MRENCLAVE value in SGX quote
  --mrsigner HEXDIGEST  Expected MRSIGNER value in SGX quote
  --pccs-url URL        Provisioning Certificate Cache Service URL (Intel
                        DCAP)
  --azure-attestation   Microsoft Azure Attestation Service (Azure DCAP)
$ sgx-ra-utils --help
usage: sgx-ra-utils [-h] [--verbose] {extract} ...

Intel SGX DCAP Quote tools

positional arguments:
  {extract}   sub-command help
    extract   Extract Quote from RA-TLS X.509 certificate

optional arguments:
  -h, --help  show this help message and exit
  --verbose   Verbose mode
```
