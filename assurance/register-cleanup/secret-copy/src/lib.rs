//! Actual private secret-transfer source and public initialization contract.
#![no_std]
pub use brynja_core::SecretMemoryError;
#[allow(dead_code)]
#[path = "../../../../crates/brynja-core/src/secret_memory_transfer.rs"]
mod transfer;
pub type Kernel = unsafe extern "C" fn(*mut u8, *const u8, usize);
pub static PROBE: Kernel = transfer::copy_bytes;
#[cfg(test)]
mod tests;
