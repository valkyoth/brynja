//! Source-bound scalar SHA-224/256 compression, not whole-API qualification.
#![no_std]
#[allow(dead_code, clippy::chunks_exact_to_as_chunks)]
#[path = "../../../../crates/brynja-hash-sha2/src/compress.rs"]
mod compress;
#[allow(dead_code)]
#[path = "../../../../crates/brynja-hash-sha2/src/hardened/compress32/native.rs"]
mod kernel;

pub type Kernel = unsafe extern "C" fn(&mut [u8; 64], &[u8; 128], &mut [u8; 640], &[u32; 64]);
pub static PROBE: Kernel = kernel::scalar;
#[cfg(test)]
mod tests;
