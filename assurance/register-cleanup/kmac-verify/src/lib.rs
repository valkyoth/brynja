//! Synthetic verification-return diagnostics, not a complete cleanup proof.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "accelerated")]
use brynja_crypto_cpu::{
    hardened_execution::KeccakSession,
    static_execution::{Authority, Health, Kernel},
};
#[cfg(feature = "accelerated")]
use brynja_mac_kmac::execution::in_place as api;
#[cfg(not(feature = "accelerated"))]
use brynja_mac_kmac::hardened_in_place as api;
use brynja_mac_kmac::{Fips202BitString, KmacError};
mod vectors;

/// Stable public fixture status values, including deliberate API rejections.
pub const EXPECTED: &[u8] = if cfg!(feature = "accelerated") {
    &[0, 1, 1, 1, 2, 3, 4]
} else {
    &[0, 1, 1, 1, 2, 3]
};

/// Explicit deployment authority; the accelerated profile never falls back.
#[cfg(feature = "accelerated")]
pub fn kernel() -> Kernel {
    if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    }
}

macro_rules! probe {
    ($name:ident, $workspace:ident, $strength:literal) => {
        /// 0 match, 1 mismatch, 2 wrong exact length, 3 short tag,
        /// 4 revoked backend, 5 invalid fixture input, 6 unexpected API result.
        /// The output is an untouched sentinel, not a secret output destination.
        #[inline(never)]
        pub extern "C" fn $name(input: &[u8; 256], _output: &mut [u8; 64], case: usize) -> u8 {
            if case >= EXPECTED.len() {
                return 5;
            }
            let marker = match input[0] {
                0x36 => 0,
                0xa7 => 1,
                _ => return 5,
            };
            let mut candidate = vectors::TAGS[$strength][marker];
            if case == 1 || case == 3 {
                candidate[0] ^= 1;
            }
            if case == 2 || case == 3 {
                candidate[128] ^= 1;
            }
            let (bytes, valid, bits) = if case == 5 {
                (&candidate[..1], 8, 8)
            } else {
                (&candidate[..], 3, if case == 4 { 1026 } else { 1027 })
            };
            let candidate = match Fips202BitString::new(bytes, valid) {
                Ok(value) => value,
                Err(_) => return 6,
            };
            let empty = match Fips202BitString::new(&[], 0) {
                Ok(value) => value,
                Err(_) => return 6,
            };
            #[cfg(feature = "accelerated")]
            let owner = match Authority::new(kernel()) {
                Ok(value) => value,
                Err(_) => return 6,
            };
            #[cfg(feature = "accelerated")]
            let mut workspace = match KeccakSession::from_static(&owner)
                .map_err(|_| ())
                .and_then(|session| api::$workspace::new(session).map_err(|_| ()))
            {
                Ok(value) => value,
                Err(_) => return 6,
            };
            #[cfg(feature = "accelerated")]
            if workspace.report().kernel != kernel() || workspace.report().health != Health::Healthy
            {
                return 6;
            }
            #[cfg(not(feature = "accelerated"))]
            let mut workspace = api::$workspace::new();
            let result = workspace
                .with(&input[..32], b"", |mut state| {
                    state.update(&input[..135])?;
                    #[cfg(feature = "accelerated")]
                    if case == 6 {
                        owner.quarantine();
                    }
                    state.verify_exact(empty, candidate, bits)
                })
                .and_then(|result| result);
            match result {
                Ok(value) => u8::from(!value.expose_public()),
                Err(KmacError::InvalidBitString) => 2,
                Err(KmacError::TagTooShort) => 3,
                #[cfg(feature = "accelerated")]
                Err(KmacError::Execution(_))
                    if case == 6 && owner.report().health == Health::Quarantined =>
                {
                    4
                }
                _ => 6,
            }
        }
    };
}
probe!(verify128, Kmac128Workspace, 0);
probe!(verify256, Kmac256Workspace, 1);

/// Identical observer ABI to the original caller fixture.
pub type Probe = extern "C" fn(&[u8; 256], &mut [u8; 64], usize) -> u8;
pub const PROBES: [(&str, Probe); 2] = [("kmac128", verify128), ("kmac256", verify256)];
