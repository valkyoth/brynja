#![no_std]

#[cfg(feature = "enabled")]
mod enabled;

#[cfg(not(feature = "enabled"))]
pub fn forbidden_default_conformance_surface() {
    let _ = brynja_mac_kmac::Kmac128::new_conformance(b"", b"");
}
