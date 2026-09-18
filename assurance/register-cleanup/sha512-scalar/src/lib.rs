//! Source-bound scalar SHA-512-family compression, not whole-API qualification.
#![no_std]
#[allow(dead_code, clippy::chunks_exact_to_as_chunks)]
#[path = "../../../../crates/brynja-hash-sha2/src/compress64.rs"]
mod compress64;
#[allow(dead_code)]
#[path = "../../../../crates/brynja-hash-sha2/src/hardened/compress64/native.rs"]
mod kernel;

pub type Kernel = unsafe extern "C" fn(&mut [u8; 64], &[u8; 128], &mut [u8; 640], &[u64; 80]);
pub static PROBE: Kernel = kernel::scalar;
#[cfg(test)]
mod tests;
