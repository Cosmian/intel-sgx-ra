"""intel_sgx_ra.quote module."""

import re
import struct
from dataclasses import asdict, dataclass
from typing import Tuple, cast

SGX_QUOTE_MAX_SIZE: int = 8192

RE_CERT: re.Pattern = re.compile(
    b"(-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----)", re.DOTALL
)

HEADER = struct.Struct("HH4sHHI32s")
REPORT_BODY = struct.Struct("16sI12s16sQQ32s32s32s32s64sHHH42s16s64s")


@dataclass
class ReportBody:  # 384 bytes
    # pylint: disable=line-too-long
    """Representation of `sgx_report_body_t` structure (in `sgx_report.h`).

    Attributes
    ----------
    cpu_svn : bytes
        CPU Security Version Number (`sgx_cpu_svn_t`, 16 bytes).
        C type: uint8_t svn[16].
        Used in the key derivation.
        See `sgx_key.h`.
    misc_select : int
        Misc select bits for the target enclave (`sgx_misc_select_t`, 4 bytes).
        Desired Extended SSA (State Save Area) frame feature (4 bytes).
        C type: uint32_t.
        Reserved for future use. Must be set to zero.
        See `sgx_attributes.h`.
    reserved1 : bytes
        Reserved for future use (20 bytes).
        C type: uint8_t reserved1[20].
        Must be set to zero.
        See `sgx_report.h`.
    isv_ext_prod_id : bytes
        Independant Software Vendor Extended Product ID (16 bytes).
        C type: sgx_isvext_prod_id_t -> typedef uint8_t sgx_isvext_prod_id_t[16].
        See `sgx_report.h`.
    flags : int
        Flags attribute (8 bytes).
        C type: uint64_t.
        Combination of the following values:
            SGX_FLAGS_INITTED (0x0000000000000001ULL):
                The enclave is initialized.
            SGX_FLAGS_DEBUG (0x0000000000000002ULL):
                The enclave is a debug enclave.
            SGX_FLAGS_MODE64BIT (0x0000000000000004ULL):
                The enclave runs in 64 bit mode.
            SGX_FLAGS_PROVISION_KEY (0x0000000000000010ULL):
                The enclave has access to a provision key.
            SGX_FLAGS_EINITTOKEN_KEY (0x0000000000000020ULL):
                The enclave has access to a launch key.
            SGX_FLAGS_KSS (0x0000000000000080ULL):
                The enclave requires the KSS feature.
        See `sgx_attributes.h`.
    xfrm : int
        X-Features Request Mask attribute (8 bytes).
        C type: uint64_t.
        Combination of the following values:
            SGX_XFRM_LEGACY (0x0000000000000003ULL):
                FPU and Intel Streaming SIMD Extensions states are saved.
            SGX_XFRM_AVX (0x0000000000000006ULL):
                Intel Advanced Vector Extensions state is saved.
        See `sgx_attributes.h`.
    mr_enclave : bytes
        MRENCLAVE measurement.
        C type: sgx_measurement_t -> uint8_t m[32].
        See `sgx_report.h`.

    References
    ----------
    .. [1] https://github.com/intel/linux-sgx/blob/sgx_2.17.1/common/inc/
       [2] https://download.01.org/intel-sgx/sgx-linux/2.17.1/docs/

    """

    cpu_svn: bytes  # 0
    misc_select: int  # 16
    reserved1: bytes  # 20
    isv_ext_prod_id: bytes  # 32
    flags: int  # 48
    xfrm: int  # 56
    mr_enclave: bytes  # 64
    reserved2: bytes  # 96
    mr_signer: bytes  # 128
    reserved3: bytes  # 160
    config_id: bytes  # 192
    isv_prod_id: int  # 256
    isv_svn: int  # 258
    config_svn: int  # 260
    reserved4: bytes  # 262
    isvn_family_id: bytes  # 304
    report_data: bytes  # 320

    @classmethod
    def from_bytes(cls, raw_report_body: bytes) -> "ReportBody":
        """Deserialize bytes of sgx_report_body structure."""
        return cls(*REPORT_BODY.unpack(raw_report_body))

    def __bytes__(self) -> bytes:
        """Serialize ReportBody."""
        return REPORT_BODY.pack(
            self.cpu_svn,
            self.misc_select,
            self.reserved1,
            self.isv_ext_prod_id,
            self.flags,
            self.xfrm,
            self.mr_enclave,
            self.reserved2,
            self.mr_signer,
            self.reserved3,
            self.config_id,
            self.isv_prod_id,
            self.isv_svn,
            self.config_svn,
            self.reserved4,
            self.isvn_family_id,
            self.report_data,
        )

    def to_dict(self):
        """Dataclass to dict."""
        return asdict(self)


@dataclass
class Header:
    """SGX quote header."""

    version: int  # 0
    sign_type: int  # 2
    epid_group_id: bytes  # 4
    qe_svn: int  # 8
    pce_svn: int  # 10
    xeid: int  # 12
    basename: bytes  # 16

    @classmethod
    def from_bytes(cls, raw_header: bytes) -> "Header":
        """Deserialize bytes of SGX quote header."""
        return cls(*HEADER.unpack(raw_header))

    def __bytes__(self) -> bytes:
        """Serialize Header."""
        return HEADER.pack(
            self.version,
            self.sign_type,
            self.epid_group_id,
            self.qe_svn,
            self.pce_svn,
            self.xeid,
            self.basename,
        )

    def to_dict(self):
        """Dataclass to dict."""
        return asdict(self)


@dataclass
class AuthData:
    """SGX auth data."""

    signature: bytes  # 0
    public_key: bytes  # 64
    qe_report: ReportBody  # 128
    qe_report_signature: bytes  # 512
    qe_auth_data: bytes  # 576
    certification_data_type: int
    certification_data: bytes

    @classmethod
    def from_bytes(cls, raw_auth_data: bytes) -> "AuthData":
        """Deserialize bytes of SGX auth data."""
        offset: int = 0
        signature: bytes = raw_auth_data[offset : offset + 64]
        offset += 64
        public_key: bytes = raw_auth_data[offset : offset + 64]
        offset += 64
        qe_report: bytes = raw_auth_data[offset : offset + 384]
        offset += 384
        qe_report_signature: bytes = raw_auth_data[offset : offset + 64]
        offset += 64
        qe_auth_data_len: int = int.from_bytes(
            raw_auth_data[offset : offset + 2], byteorder="little"
        )
        offset += 2
        qe_auth_data: bytes = raw_auth_data[offset : offset + qe_auth_data_len]
        offset += qe_auth_data_len
        certification_data_type: int = int.from_bytes(
            raw_auth_data[offset : offset + 2], byteorder="little"
        )
        offset += 2
        certification_data_len: int = int.from_bytes(
            raw_auth_data[offset : offset + 4], byteorder="little"
        )
        offset += 4
        certification_data: bytes = raw_auth_data[
            offset : offset + certification_data_len
        ]
        offset += certification_data_len

        assert len(raw_auth_data) == offset

        return cls(
            signature,
            public_key,
            ReportBody.from_bytes(qe_report),
            qe_report_signature,
            qe_auth_data,
            certification_data_type,
            certification_data,
        )

    def __bytes__(self) -> bytes:
        """Serialize AuthData."""
        return (
            self.signature
            + self.public_key
            + bytes(self.qe_report)
            + self.qe_report_signature
            + len(self.qe_auth_data).to_bytes(2, byteorder="little")
            + self.qe_auth_data
            + self.certification_data_type.to_bytes(2, byteorder="little")
            + len(self.certification_data).to_bytes(4, byteorder="little")
            + self.certification_data
        )

    def to_dict(self):
        """Dataclass to dict."""
        return asdict(self)


@dataclass
class Quote:
    """SGX quote structure."""

    header: Header  # 0
    report_body: ReportBody  # 48
    auth_data_len: int  # 432
    auth_data: AuthData  # 436

    @classmethod
    def from_bytes(cls, raw_quote: bytes) -> "Quote":
        """Deserialize bytes of sgx_quote structure."""
        view: memoryview = memoryview(raw_quote)

        offset: int = 0

        header: Header = Header.from_bytes(bytes(view[offset : offset + 48]))
        offset += 48

        report_body: ReportBody = ReportBody.from_bytes(
            bytes(view[offset : offset + 384])
        )
        offset += 384

        auth_data_len: int = int.from_bytes(
            view[offset : offset + 4], byteorder="little"
        )
        offset += 4
        assert auth_data_len == len(raw_quote[offset:])

        raw_auth_data: bytes = bytes(view[offset : offset + auth_data_len])
        offset += auth_data_len
        assert (
            len(raw_quote) == offset
        ), f"Expected length is {len(raw_quote)} found {offset}"
        auth_data: AuthData = AuthData.from_bytes(raw_auth_data)

        return cls(
            header,
            report_body,
            auth_data_len,
            auth_data,
        )

    def __bytes__(self) -> bytes:
        """Serialize Quote."""
        return (
            bytes(self.header)
            + bytes(self.report_body)
            + self.auth_data_len.to_bytes(4, byteorder="little")
            + bytes(self.auth_data)
        )

    def certs(self) -> Tuple[bytes, bytes, bytes]:
        """Find all certificates in auth data."""
        return cast(
            Tuple[bytes, bytes, bytes],
            tuple(re.findall(RE_CERT, self.auth_data.certification_data)),
        )

    def to_dict(self):
        """Dataclass to dict."""
        return asdict(self)
