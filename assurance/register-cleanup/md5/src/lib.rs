//! Source-bound MD5 observers; not native qualification.
#![no_std]
#[cfg(test)]
#[path = "../../../../crates/brynja-legacy-md5/src/cpu/constants.rs"]
mod constants;
#[cfg(all(test, target_os = "linux"))]
mod guard_pages;
#[cfg(target_arch = "x86_64")]
#[path = "../../../../crates/brynja-legacy-md5/src/cpu/x86_secret/kernel.rs"]
pub mod kernel;
#[cfg(target_arch = "aarch64")]
#[path = "../../../../crates/brynja-legacy-md5/src/cpu/arm_secret/kernel.rs"]
pub mod kernel;
#[cfg(test)]
mod tests;
