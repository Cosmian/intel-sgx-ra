from typing import Optional

class Tcb:
    @property
    def compsvn(self) -> bytes: ...
    @property
    def pcesvn(self) -> int: ...
    @property
    def cpusvn(self) -> bytes: ...

class Configuration:
    @property
    def dynamic_platform(self) -> bool: ...
    @property
    def cached_keys(self) -> bool: ...
    @property
    def smt_enabled(self) -> bool: ...

class SgxPckExtension:
    @property
    def ppid(self) -> bytes: ...
    @property
    def tcb(self) -> Tcb: ...
    @property
    def pceid(self) -> bytes: ...
    @property
    def fmspc(self) -> bytes: ...
    @property
    def sgx_type(self) -> int: ...
    @property
    def platform_instance_id(self) -> Optional[bytes]: ...
    @property
    def configuration(self):
        Optional[Configuration]: ...

def sgx_pck_extension_from_pem(pem: bytes) -> SgxPckExtension: ...
