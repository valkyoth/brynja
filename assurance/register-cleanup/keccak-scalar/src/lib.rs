//! Source-bound baseline Keccak, not whole-API qualification.
#![no_std]
#[allow(dead_code, clippy::chunks_exact_to_as_chunks)]
#[path = "../../../../crates/brynja-hash-sha3/src/keccak.rs"]
mod keccak;
#[allow(dead_code)]
#[path = "../../../../crates/brynja-hash-sha3/src/hardened/permutation/native.rs"]
mod kernel;
pub type Kernel =
    unsafe extern "C" fn(&mut [u8; 200], &mut [u8; 40], &mut [u8; 40], &mut [u8; 200], &[u64; 24]);
pub static PROBE: Kernel = kernel::scalar;
#[cfg(test)]
mod tests;
