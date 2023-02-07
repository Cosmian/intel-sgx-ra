"""intel_sgx_ra.quote module."""

import re
import struct
from dataclasses import asdict, dataclass
from typing import Tuple, cast

SGX_QUOTE_MAX_SIZE: int = 8192

RE_CERT: re.Pattern = re.compile(
    b"(-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----)", re.DOTALL
)

REPORT_BODY = struct.Struct(">16sI12s16sQQ32s32s32s32s64sHHH42s16s64s")
QUOTE = struct.Struct(">HH4sHHI32s384s")


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
class Quote:
    """SGX quote structure."""

    version: int  # 0
    sign_type: int  # 2
    epid_group_id: bytes  # 4
    qe_svn: int  # 8
    pce_svn: int  # 10
    xeid: int  # 12
    basename: bytes  # 16
    report_body: ReportBody  # 48
    signature_len: int  # 432
    signature: bytes  # 436

    @classmethod
    def from_bytes(cls, raw_quote: bytes) -> "Quote":
        """Deserialize bytes of sgx_quote structure."""
        view: memoryview = memoryview(raw_quote)

        offset: int = 48 + 384
        (
            version,
            sign_type,
            epid_group_id,
            qe_svn,
            pce_svn,
            xeid,
            basename,
            raw_report_body,
        ) = QUOTE.unpack(view[:offset])
        report_body: ReportBody = ReportBody.from_bytes(raw_report_body)
        signature_len: int = int.from_bytes(
            view[offset : offset + 4], byteorder="little"
        )
        offset += 4
        signature: bytes = bytes(view[offset:])

        assert len(signature) == signature_len

        return cls(
            version,
            sign_type,
            epid_group_id,
            qe_svn,
            pce_svn,
            xeid,
            basename,
            report_body,
            signature_len,
            signature,
        )

    def __bytes__(self) -> bytes:
        """Serialize Quote."""
        return (
            QUOTE.pack(
                self.version,
                self.sign_type,
                self.epid_group_id,
                self.qe_svn,
                self.pce_svn,
                self.xeid,
                self.basename,
                bytes(self.report_body),
            )
            + self.signature_len.to_bytes(4, byteorder="little")
            + self.signature
        )

    def certs(self) -> Tuple[bytes, bytes, bytes]:
        """Find all certificates in signature field."""
        return cast(
            Tuple[bytes, bytes, bytes], tuple(re.findall(RE_CERT, self.signature))
        )

    def to_dict(self):
        """Dataclass to dict."""
        return asdict(self)
