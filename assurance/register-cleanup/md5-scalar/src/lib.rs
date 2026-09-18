//! Actual scalar source, isolated from high-level ownership/clearing claims.
#![no_std]
#[allow(dead_code)]
#[path = "../../../../crates/brynja-legacy-md5/src/cpu/constants.rs"]
mod constants;
use constants::CONSTANTS;
#[allow(dead_code)]
#[path = "../../../../crates/brynja-legacy-md5/src/compress/native.rs"]
mod kernel;

pub type Kernel = unsafe extern "C" fn(&mut [u8; 16], &[u8; 64], &[u32; 64], &[u32; 16]);
pub static PROBE: Kernel = kernel::scalar;

#[cfg(test)]
mod tests;
