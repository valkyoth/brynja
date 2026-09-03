#![no_std]

use brynja_mac_kmac::Kmac128;

pub fn forbidden_default_conformance_surface() {
    let _ = Kmac128::new_conformance(b"", b"");
}
