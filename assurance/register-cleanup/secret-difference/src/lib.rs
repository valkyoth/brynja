//! Development-only observer of the actual borrowed difference boundary.
#![no_std]
#[allow(dead_code)]
#[path = "../../../../crates/brynja-core/src/secret_memory_difference.rs"]
mod difference;
pub type Kernel = unsafe extern "C" fn(*mut u8, *const u8, *const u8);
pub static PROBE: Kernel = difference::accumulate_byte;
#[cfg(test)]
mod tests;
