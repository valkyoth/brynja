//! Synthetic-only scoped SP 800-185 probes; no cleanup qualification claim.
//! KMAC borrows the first 32 input bytes as its key, independently of message length.
//! TupleHash has one item; ParallelHash borrows an eight-byte leaf buffer.
use crate::Probe;
#[cfg(feature = "accelerated")]
use brynja_crypto_cpu::hardened_execution::KeccakSession;
#[cfg(feature = "accelerated")]
use brynja_hash_parallel::execution::in_place as parallel_api;
#[cfg(not(feature = "accelerated"))]
use brynja_hash_parallel::hardened_in_place as parallel_api;
#[cfg(feature = "accelerated")]
use brynja_hash_tuple::execution::in_place as tuple_api;
#[cfg(not(feature = "accelerated"))]
use brynja_hash_tuple::hardened_in_place as tuple_api;
#[cfg(feature = "accelerated")]
use brynja_mac_kmac::execution::in_place as kmac_api;
#[cfg(not(feature = "accelerated"))]
use brynja_mac_kmac::hardened_in_place as kmac_api;

#[cfg(feature = "accelerated")]
macro_rules! create {
    (parallel, $workspace:path, $owner:ident) => {
        <$workspace>::new(
            KeccakSession::from_static(&$owner).map_err(|_| ())?,
            KeccakSession::from_static(&$owner).map_err(|_| ())?,
        )
        .map_err(|_| ())
    };
    ($family:ident, $workspace:path, $owner:ident) => {
        <$workspace>::new(KeccakSession::from_static(&$owner).map_err(|_| ())?).map_err(|_| ())
    };
}
#[cfg(feature = "accelerated")]
macro_rules! valid {
    (parallel, $workspace:ident) => {
        crate::accelerated::valid($workspace.root_report())
            && crate::accelerated::valid($workspace.leaf_report())
    };
    ($family:ident, $workspace:ident) => {
        crate::accelerated::valid($workspace.report())
    };
}

macro_rules! setup {
    (kmac, $w:ident, $input:ident, $block:ident, $callback:expr) => {
        $w.with(&$input[..32], b"", $callback)
    };
    (tuple, $w:ident, $input:ident, $block:ident, $callback:expr) => {
        $w.with(b"", $callback)
    };
    (parallel, $w:ident, $input:ident, $block:ident, $callback:expr) => {
        $w.with(&mut $block, b"", $callback)
    };
}
macro_rules! absorb {
    (tuple, $state:ident, $input:expr) => {
        $state.push_item($input)
    };
    ($family:ident, $state:ident, $input:expr) => {
        $state.update($input)
    };
}
macro_rules! finish {
    (fixed, $state:ident, $output:expr, $expected:ident) => {
        match $state.finalize_secret($output) {
            Ok(secret) => {
                let status = u8::from($expected.is_some_and(|value| value != secret.expose())) * 3;
                drop(secret);
                status
            }
            Err(_) => 1,
        }
    };
    (xof, $state:ident, $output:expr, $expected:ident) => {
        match $state.finalize_xof() {
            Ok(mut reader) => match reader.squeeze_secret($output) {
                Ok(secret) => {
                    let status =
                        u8::from($expected.is_some_and(|value| value != secret.expose())) * 3;
                    drop(secret);
                    status
                }
                Err(_) => 1,
            },
            Err(_) => 1,
        }
    };
}

macro_rules! probes {
    ($(($name:ident, $run:ident, $workspace:path, $family:ident, $kind:ident)),+ $(,)?) => {
        $(
            /// 0 success, 1 API failure, 2 invalid fixture length, 3 vector mismatch, 4 authority failure.
            /// The optional known-answer check uses only synthetic non-secret values.
            #[inline(never)]
            fn $run(input: &[u8; 256], output: &mut [u8; 64], length: usize, expected: Option<&[u8]>, _revoke: bool) -> u8 {
                let Some(message) = input.get(..length) else { return 2; };
                #[cfg(feature = "accelerated")]
                let owner = match crate::accelerated::authority() { Ok(owner) => owner, Err(_) => return 4 };
                #[cfg(feature = "accelerated")]
                let mut workspace = {
                    match (|| create!($family, $workspace, owner))() { Ok(value) => value, Err(()) => return 4 }
                };
                #[cfg(not(feature = "accelerated"))]
                let mut workspace = <$workspace>::new();
                #[cfg(feature = "accelerated")]
                {
                    if !valid!($family, workspace) { return 4; }
                    if _revoke { owner.quarantine(); }
                }
                // Used only by ParallelHash; retained here so every probe has identical scaffolding.
                #[allow(unused_mut, unused_variables)]
                let mut block = [0_u8; 8];
                let result = setup!($family, workspace, input, block, |mut state| {
                    if absorb!($family, state, message).is_err() { return 1; }
                    finish!($kind, state, &mut output[..32], expected)
                });
                match result { Ok(status) => status, Err(_) => 1 }
            }
            /// Observe the same worker used by the independent known-answer test.
            #[inline(never)]
            pub extern "C" fn $name(input: &[u8;256], output: &mut [u8;64], length: usize) -> u8 {
                $run(input, output, length, None, false)
            }
        )+
        /// Identical synthetic-input observer ABI; every owned output is 32 bytes.
        pub const PROBES: [(&str, Probe, usize); 12] = [$( (stringify!($name), $name, 32) ),+];
        /// Uses the actual probe worker before it drops its output owner.
        pub fn check_known(name: &str, input: &[u8;256], output: &mut [u8;64], length: usize, expected: &[u8]) -> u8 {
            match name { $( stringify!($name) => $run(input, output, length, Some(expected), false), )+ _ => 2 }
        }
        /// Test the actual worker after authority revocation, before accepting input.
        #[cfg(feature = "accelerated")]
        pub fn check_revoked(name: &str, input: &[u8;256], output: &mut [u8;64]) -> u8 {
            match name { $( stringify!($name) => $run(input, output, 135, None, true), )+ _ => 2 }
        }
    };
}
probes!(
    (
        kmac128,
        run_kmac128,
        kmac_api::Kmac128Workspace,
        kmac,
        fixed
    ),
    (
        kmac256,
        run_kmac256,
        kmac_api::Kmac256Workspace,
        kmac,
        fixed
    ),
    (
        kmacxof128,
        run_kmacxof128,
        kmac_api::KmacXof128Workspace,
        kmac,
        xof
    ),
    (
        kmacxof256,
        run_kmacxof256,
        kmac_api::KmacXof256Workspace,
        kmac,
        xof
    ),
    (
        tuple128,
        run_tuple128,
        tuple_api::TupleHash128Workspace,
        tuple,
        fixed
    ),
    (
        tuple256,
        run_tuple256,
        tuple_api::TupleHash256Workspace,
        tuple,
        fixed
    ),
    (
        tuplexof128,
        run_tuplexof128,
        tuple_api::TupleHashXof128Workspace,
        tuple,
        xof
    ),
    (
        tuplexof256,
        run_tuplexof256,
        tuple_api::TupleHashXof256Workspace,
        tuple,
        xof
    ),
    (
        parallel128,
        run_parallel128,
        parallel_api::ParallelHash128Workspace,
        parallel,
        fixed
    ),
    (
        parallel256,
        run_parallel256,
        parallel_api::ParallelHash256Workspace,
        parallel,
        fixed
    ),
    (
        parallelxof128,
        run_parallelxof128,
        parallel_api::ParallelHashXof128Workspace,
        parallel,
        xof
    ),
    (
        parallelxof256,
        run_parallelxof256,
        parallel_api::ParallelHashXof256Workspace,
        parallel,
        xof
    ),
);
