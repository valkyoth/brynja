//! Development probe of the actual production Keccak transposition source.
#![no_std]

#[repr(C)]
pub struct Workspace {
    state: [[u8; 32]; 25],
    columns: [[u8; 32]; 5],
    deltas: [[u8; 32]; 5],
    staging: [[u8; 32]; 25],
}

#[allow(dead_code)]
#[path = "../../../../crates/brynja-crypto-cpu/src/keccak_hardened_batch/transfer.rs"]
mod actual;

pub type Probe = unsafe extern "C" fn(*mut u8, *const u8, usize);
pub static PROBES: [Probe; 2] = [actual::transpose::<true>, actual::transpose::<false>];

#[cfg(test)]
mod tests;
