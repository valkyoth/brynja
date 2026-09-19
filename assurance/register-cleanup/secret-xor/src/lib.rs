//! Development-only immediate register observer of the actual borrowed boundary.
#![no_std]
pub use brynja_core::SecretBitRangeError;
#[allow(dead_code)]
#[path = "../../../../crates/brynja-core/src/secret_memory_xor.rs"]
mod xor;
pub type Kernel = unsafe extern "C" fn(*mut u8, *const u8, u32, u32, u32);
pub static PROBE: Kernel = xor::xor_bits;
#[cfg(test)]
mod tests;
