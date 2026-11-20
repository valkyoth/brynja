//! Private development-only foundation for the bounded fault-integrity scope.
//! This is NOT a fault detector, admitted backend or deployment API.
//! The secondary engine uses no primary arithmetic/substitution/expansion helpers.
//! Shared Error/Scratch/core clearing remain common-mode dependencies.

use super::{Error, Scratch};

mod admission;
mod failure;
use failure::ProfileFailure;
// Private receipt experiment used by the test transaction, never production.
#[cfg(brynja_fault_primitives)]
mod authorization_model;
mod capture;
#[cfg(test)]
mod cipher_avs_tests;
#[cfg(test)]
mod cipher_tests;
mod coefficients;
mod linear;
mod primary;
mod retained;
mod schedule;
#[cfg(test)]
mod tests;
mod transaction;
// Explicit evidence-build flag AND cfg(test) are required. The primary field
// fixture is also gated by both; no Cargo feature exposes corruption controls.
#[cfg(all(test, brynja_fault_evidence))]
mod corruption_tests;

// Sixteen lanes: two groups of eight bit planes, least significant bit first.
// Each u8 plane represents one bit of eight different bytes. No Copy/Clone.
struct Planes(Scratch<16>);

fn read(bytes: &[u8], position: usize) -> Result<u8, Error> {
    bytes.get(position).copied().ok_or(Error::SecretMemory)
}

impl Planes {
    fn new() -> Self {
        Self(Scratch::new())
    }

    // Representation conversion, NOT the future independently opaque D3 capture.
    fn load(&mut self, bytes: &[u8; 16]) -> Result<(), Error> {
        self.0.0.fill(0);
        for (lane, byte) in bytes.iter().enumerate() {
            for bit in 0..8 {
                let position = (lane / 8).wrapping_mul(8).wrapping_add(bit);
                let plane = self.0.0.get_mut(position).ok_or(Error::SecretMemory)?;
                *plane |= ((byte >> bit) & 1) << (lane % 8);
            }
        }
        Ok(())
    }

    // Caller output is not guarded here: only public fixtures use this workbench.
    fn store(&self, bytes: &mut [u8; 16]) -> Result<(), Error> {
        for (lane, byte) in bytes.iter_mut().enumerate() {
            *byte = 0;
            for bit in 0..8 {
                let position = (lane / 8).wrapping_mul(8).wrapping_add(bit);
                *byte |= ((read(&self.0.0, position)? >> (lane % 8)) & 1) << bit;
            }
        }
        Ok(())
    }

    // Independent Boolean substitution. Every memory index and branch depends
    // only on public direction, plane, coefficient or monomial position.
    // Deliberately simple ANF evaluator, not an optimized gate-count circuit.
    // No constant-time/emitted-code/fault-independence claim is made yet.
    fn substitute(&mut self, inverse: bool) -> Result<(), Error> {
        let coefficients = if inverse {
            &coefficients::INVERSE
        } else {
            &coefficients::FORWARD
        };
        let mut output = Scratch::<16>::new();
        let mut term = Scratch::<1>::new();
        for half in 0usize..2 {
            let offset = half.wrapping_mul(8);
            for (monomial, coefficient) in coefficients.iter().enumerate() {
                let product = term.0.first_mut().ok_or(Error::SecretMemory)?;
                *product = u8::MAX; // Empty product, independently in each lane.
                for bit in 0usize..8 {
                    if monomial & (1usize << bit) != 0 {
                        *product &= read(&self.0.0, offset.wrapping_add(bit))?;
                    }
                }
                // Source-only persistent secondary constant fault. The hook is
                // absent from every non-test build and all native evidence ELFs.
                #[cfg(all(test, brynja_fault_evidence))]
                let coefficient = if monomial == 0 || monomial == 255 {
                    corruption_tests::coefficient_fault(monomial, *coefficient, *product)
                } else {
                    *coefficient
                };
                #[cfg(not(all(test, brynja_fault_evidence)))]
                let coefficient = *coefficient;
                for bit in 0usize..8 {
                    let plane = output
                        .0
                        .get_mut(offset.wrapping_add(bit))
                        .ok_or(Error::SecretMemory)?;
                    *plane ^= *product & 0u8.wrapping_sub((coefficient >> bit) & 1);
                }
            }
        }
        self.0.0.copy_from_slice(&output.0);
        // Scratch clears explicit arrays on ordinary return/error/unwind only;
        // scalar compiler copies/registers and physical observations are excluded.
        Ok(())
    }
}
