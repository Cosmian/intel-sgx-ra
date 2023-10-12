use pyo3::{exceptions::PyException, prelude::*, types::PyBytes};
use sgx_pck_extension::extension::SgxPckExtension;

#[derive(Clone)]
#[pyclass(name = "Configuration", get_all)]
pub struct PyConfiguration {
    pub dynamic_platform: bool,
    pub cached_keys: bool,
    pub smt_enabled: bool,
}

#[derive(Clone)]
#[pyclass(name = "Tcb", get_all)]
pub struct PyTcb {
    pub compsvn: Py<PyBytes>,
    pub pcesvn: u16,
    pub cpusvn: Py<PyBytes>,
}

#[pyclass(name = "SgxPckExtension", get_all)]
pub struct PySgxPckExtension {
    pub ppid: Py<PyBytes>,
    pub tcb: PyTcb,
    pub pceid: Py<PyBytes>,
    pub fmspc: Py<PyBytes>,
    pub sgx_type: u8,
    pub platform_instance_id: Option<Py<PyBytes>>,
    pub configuration: Option<PyConfiguration>,
}

impl From<SgxPckExtension> for PySgxPckExtension {
    fn from(sgx_pck_extension: SgxPckExtension) -> PySgxPckExtension {
        let ppid: Py<PyBytes> =
            Python::with_gil(|py| PyBytes::new(py, sgx_pck_extension.ppid.as_slice()).into());

        let compsvn: Py<PyBytes> = Python::with_gil(|py| {
            PyBytes::new(py, sgx_pck_extension.tcb.compsvn.as_slice()).into()
        });

        let cpusvn: Py<PyBytes> =
            Python::with_gil(|py| PyBytes::new(py, sgx_pck_extension.tcb.cpusvn.as_slice()).into());

        let pceid: Py<PyBytes> =
            Python::with_gil(|py| PyBytes::new(py, sgx_pck_extension.pceid.as_slice()).into());

        let fmspc: Py<PyBytes> =
            Python::with_gil(|py| PyBytes::new(py, sgx_pck_extension.fmspc.as_slice()).into());

        let platform_instance_id: Option<Py<PyBytes>> =
            sgx_pck_extension
                .platform_instance_id
                .map(|platform_instance_id| {
                    Python::with_gil(|py| PyBytes::new(py, platform_instance_id.as_slice()).into())
                });

        PySgxPckExtension {
            ppid,
            tcb: PyTcb {
                compsvn,
                pcesvn: sgx_pck_extension.tcb.pcesvn,
                cpusvn,
            },
            pceid,
            fmspc,
            sgx_type: sgx_pck_extension.sgx_type as u8,
            platform_instance_id,
            configuration: sgx_pck_extension
                .configuration
                .map(|configuration| PyConfiguration {
                    dynamic_platform: configuration.dynamic_platform,
                    cached_keys: configuration.cached_keys,
                    smt_enabled: configuration.smt_enabled,
                }),
        }
    }
}

#[pyfunction]
fn sgx_pck_extension_from_pem(_py: Python<'_>, pem: &[u8]) -> PyResult<PySgxPckExtension> {
    let pck_extension = SgxPckExtension::from_pem_certificate(pem)
        .map_err(|e| PyException::new_err(e.to_string()))?;

    Ok(pck_extension.into())
}

#[pymodule]
#[pyo3(name = "lib_sgx_dcap_ratls")]
fn sgx_dcap_ratls(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyTcb>()?;
    m.add_class::<PyConfiguration>()?;
    m.add_class::<PySgxPckExtension>()?;
    m.add_function(wrap_pyfunction!(sgx_pck_extension_from_pem, m)?)?;
    Ok(())
}
