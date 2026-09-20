//! Explicit static test deployment only, without portable fallback.
use brynja_crypto_cpu::static_execution::{Authority, Error, Health, Kernel, Report};

pub fn kernel() -> Kernel {
    if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    }
}

pub fn authority() -> Result<Authority, Error> {
    Authority::new(kernel())
}

pub fn valid(report: Report) -> bool {
    report.kernel == kernel() && report.health == Health::Healthy
}
