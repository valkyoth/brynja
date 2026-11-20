//! Private capture candidate using the existing reviewed core transfer boundary.
//! This is not admission or D3 qualification of its linked call sites. Core uses
//! opaque assembly only on x86-64/little-endian AArch64 outside Miri/Kani;
//! everywhere else this workbench exercises a portable functional model.
use super::Error;

// Never seed the second replica from the first. Both calls must freshly read
// the common caller source. Caller source corruption affecting both is excluded.
// The caller must hold clearing guards across this operation and any error.
#[inline(never)]
pub(super) fn pair(source: &[u8], first: &mut [u8], second: &mut [u8]) -> Result<(), Error> {
    if source.len() != first.len() || source.len() != second.len() {
        return Err(Error::SecretMemory);
    }
    brynja_core::copy_secret_region(first, source)?;
    #[cfg(all(test, brynja_fault_evidence))]
    evidence_tests::checkpoint(evidence_tests::Stage::AfterFirst, first)?;
    brynja_core::copy_secret_region(second, source)?;
    #[cfg(all(test, brynja_fault_evidence))]
    evidence_tests::checkpoint(evidence_tests::Stage::AfterSecond, second)?;
    Ok(())
}

#[cfg(all(test, brynja_fault_evidence))]
pub(super) mod evidence_tests;
#[cfg(test)]
mod tests;
