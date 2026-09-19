//! Development-only observer of the actual borrowed predicate boundary.
#![no_std]
#[allow(dead_code)]
#[path = "../../../../crates/brynja-core/src/secret_memory_predicate.rs"]
mod predicate;
pub type Kernel = unsafe extern "C" fn(*const u8, u8) -> u32;
pub static PROBE: Kernel = predicate::mask_is_zero;
#[cfg(test)]
mod tests;
