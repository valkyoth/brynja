//! Development probe of the actual production transposition source.
#![no_std]

#[repr(C, align(32))]
pub struct Workspace {
    initial: [[u8; 32]; 8],
    schedule: [[u8; 32]; 80],
    work: [[u8; 32]; 8],
    temporary: [[u8; 32]; 6],
}

#[allow(dead_code)]
#[path = "../../../../crates/brynja-crypto-cpu/src/sha512_hardened_batch/transfer.rs"]
mod actual;

pub type Probe = unsafe extern "C" fn(*mut u8, *const u8, usize, u32);
// Force the same three production monomorphizations into emitted library code.
pub static PROBES: [Probe; 3] = [
    actual::transpose::<8, true>,
    actual::transpose::<16, true>,
    actual::transpose::<8, false>,
];

#[cfg(test)]
mod tests;
