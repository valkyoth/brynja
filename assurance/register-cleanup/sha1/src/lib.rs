//! Source-bound SHA-1 register and memory boundary observers; not native qualification.
#![no_std]
#[cfg(all(test, target_os = "linux"))]
mod guard_pages;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[path = "../../../../crates/brynja-legacy-sha1/src/cpu/x86_sha1/secret.rs"]
pub mod kernel;
#[cfg(target_arch = "aarch64")]
#[path = "../../../../crates/brynja-legacy-sha1/src/cpu/aarch64_sha1/secret.rs"]
pub mod kernel;
#[cfg(test)]
mod tests;
