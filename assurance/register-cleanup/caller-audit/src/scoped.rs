//! Whole-call diagnostics with locally constructed, exclusively borrowed workspaces.
//! Secret-free construction precedes `with`; no populated owner moves afterward.
//! The wrapper is part of the observed boundary, not a complete erasure proof.
use crate::Probe;

macro_rules! probe {
    ($name:ident, $workspace:path, $width:literal) => {
        /// Same synthetic-input/output/status ABI as the movable diagnostic.
        #[inline(never)]
        pub extern "C" fn $name(input: &[u8; 256], output: &mut [u8; 64], length: usize) -> u8 {
            let Some(input) = input.get(..length) else {
                return 2;
            };
            let mut workspace = <$workspace>::new();
            workspace.with(|mut state| {
                if state.update(input).is_err() {
                    return 1;
                }
                match state.finalize_secret(&mut output[..$width]) {
                    Ok(secret) => {
                        drop(secret);
                        0
                    }
                    Err(_) => 1,
                }
            })
        }
    };
}

probe!(
    sha256,
    brynja_hash_sha2::hardened_in_place::Sha256Workspace,
    32
);
probe!(
    sha512,
    brynja_hash_sha2::hardened_in_place::Sha512Workspace,
    64
);
probe!(
    sha3,
    brynja_hash_sha3::hardened_in_place::Sha3_256Workspace,
    32
);
probe!(
    sha1,
    brynja_legacy_sha1::hardened_in_place::Sha1Workspace,
    20
);
probe!(md5, brynja_legacy_md5::hardened_in_place::Md5Workspace, 16);

/// Corresponding scoped wrappers; never aliases of the movable wrappers.
pub const PROBES: [(&str, Probe, usize); 5] = [
    ("sha256", sha256, 32),
    ("sha512", sha512, 64),
    ("sha3", sha3, 32),
    ("sha1", sha1, 20),
    ("md5", md5, 16),
];
