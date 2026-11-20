//! Candidate receipt representation for review, NOT release authorization.
//!
//! Each of sixteen lanes freshly reads the destination and recomputes BOTH
//! full comparisons. No Choice/Boolean is expanded into a wide word. However,
//! loop bounds, pointer selection, expected constants, final Rust predicates
//! and control flow remain unqualified. A compiler can merge the final guards.
//! The private transaction now uses fresh receipts for its tentative write.
//! Its readback, lifecycle and final return remain unqualified Rust control flow.
use super::{Error, Scratch};
use brynja_core::{copy_secret_region, fault_comparison_workbench};

const LANES: usize = 16;
const BYTES: usize = LANES * 2;
const FORWARD: [u8; 2] = [0xa5, 0x3c];
const REVERSE: [u8; 2] = [0x5a, 0xc3];

// No caller-supplied receipt, retained receipt or alternate proposed-data
// parameter: construct, use once and drop inside this function. This narrows
// ordinary API misuse; it does NOT prevent machine faults between these steps.
pub(super) fn copy_fresh(
    output: &mut [u8; 16],
    primary: &[u8; 16],
    secondary: &[u8; 16],
) -> Result<(), Error> {
    let candidate = Candidate::observe(primary, primary, secondary)?;
    let mut report = Scratch::<1>::new();
    fault_comparison_workbench::tentative_copy_16(
        output,
        primary,
        &candidate.forward.0,
        &candidate.reverse.0,
        &mut report.0[0],
    );
    // This diagnostic can fail an operation, but is NOT sufficient for success:
    // the transaction must independently reload/check the actual destination.
    if report.0[0] != 0xa5 {
        return Err(Error::SecretMemory);
    }
    Ok(())
}

// Final public/secret permit experiment. Invalidate before observing the actual
// destination; only the two opaque receipt guards can restore the live codeword.
// The diagnostic and a separate fresh lifecycle read must BOTH accept. This
// closes the observed shared-readback-branch bypass, not the full fault model.
pub(super) fn permit_fresh(
    destination: &[u8],
    primary: &[u8; 16],
    secondary: &[u8; 16],
    state: &mut [u8; 16],
    denied: &[u8; 16],
    permitted: &[u8; 16],
) -> Result<(), Error> {
    state.copy_from_slice(denied);
    let destination = destination.try_into().map_err(|_| Error::SecretMemory)?;
    let candidate = Candidate::observe(destination, primary, secondary)?;
    let mut report = Scratch::<1>::new();
    fault_comparison_workbench::tentative_copy_16(
        state,
        permitted,
        &candidate.forward.0,
        &candidate.reverse.0,
        &mut report.0[0],
    );
    if report.0[0] != 0xa5 {
        return Err(Error::SecretMemory);
    }
    Ok(())
}

// Not Clone/Copy; creation and consumption stay inside this private model.
// Receipts contain mismatch information and must never be exposed by an API.
struct Candidate {
    forward: Scratch<BYTES>,
    reverse: Scratch<BYTES>,
}

impl Candidate {
    fn observe(
        destination: &[u8; 16],
        primary: &[u8; 16],
        secondary: &[u8; 16],
    ) -> Result<Self, Error> {
        let mut result = Self {
            forward: Scratch::new(),
            reverse: Scratch::new(),
        };
        // Separate loops/calls and fresh observed/accumulator storage for each
        // lane. This is functional separation, NOT a linked-caller claim.
        for pair in result.forward.0.as_chunks_mut::<2>().0 {
            let mut observed = Scratch::<16>::new();
            let mut residual = Scratch::<2>::new();
            copy_secret_region(&mut observed.0, destination)?;
            fault_comparison_workbench::forward_16(
                &mut residual.0,
                &observed.0,
                primary,
                secondary,
            );
            for ((byte, difference), code) in pair.iter_mut().zip(residual.0.iter()).zip(FORWARD) {
                *byte = code ^ difference;
            }
        }
        for pair in result.reverse.0.as_chunks_mut::<2>().0.iter_mut().rev() {
            let mut observed = Scratch::<16>::new();
            let mut residual = Scratch::<2>::new();
            copy_secret_region(&mut observed.0, destination)?;
            fault_comparison_workbench::reverse_16(
                &mut residual.0,
                &observed.0,
                primary,
                secondary,
            );
            for ((byte, mask), code) in pair.iter_mut().zip(residual.0.iter()).zip(REVERSE) {
                *byte = code ^ !mask;
            }
        }
        Ok(result)
    }

    // Full-byte validators deliberately return ordinary Result here. Their
    // presence does not protect a final branch/flag, and no caller may use this
    // prototype as permission to publish a block. Both are evaluated on errors.
    fn inspect_forward(&self) -> Result<(), Error> {
        let mut difference = Scratch::<1>::new();
        for (actual, code) in self.forward.0.iter().zip(FORWARD.into_iter().cycle()) {
            difference.0[0] |= actual ^ code;
        }
        if difference.0[0] == 0 {
            Ok(())
        } else {
            Err(Error::SecretMemory)
        }
    }

    fn inspect_reverse(&self) -> Result<(), Error> {
        let mut agreement = Scratch::<1>::new();
        agreement.0[0] = 0xff;
        for (actual, code) in self
            .reverse
            .0
            .iter()
            .rev()
            .zip(REVERSE.into_iter().rev().cycle())
        {
            agreement.0[0] &= !(actual ^ code);
        }
        if agreement.0[0] == 0xff {
            Ok(())
        } else {
            Err(Error::SecretMemory)
        }
    }

    fn consume(self) -> Result<(), Error> {
        let first = self.inspect_forward();
        let second = self.inspect_reverse();
        first.and(second)
        // Both clearing owners drop on success AND failure. This is type-level
        // move consumption only, not physical anti-replay or operation binding.
    }
}

#[cfg(all(test, brynja_fault_evidence))]
mod evidence_tests;
#[cfg(test)]
mod tests;
