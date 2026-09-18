//! Actual private scalar source, without high-level ownership claims.
#![no_std]
#[allow(dead_code)]
#[path = "../../../../crates/brynja-legacy-sha1/src/compress/native.rs"]
mod kernel;

pub type Kernel = unsafe extern "C" fn(&mut [u8; 20], &[u8; 64], &mut [u8; 320]);
pub static PROBE: Kernel = kernel::scalar;

#[cfg(test)]
mod tests;
