//! Development-only observer of the actual private borrowed-byte boundary.
#![no_std]
#[allow(dead_code)]
#[path = "../../../../crates/brynja-core/src/secret_memory_mask.rs"]
mod mask;
pub type Kernel = unsafe extern "C" fn(*mut u8, u8, u8);
pub static PROBE: Kernel = mask::mask_byte;
#[cfg(test)]
mod tests;
