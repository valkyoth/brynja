//! Synthetic-only scoped SP 800-185 probes; no cleanup qualification claim.
//! KMAC borrows the first 32 input bytes as its key, independently of message length.
//! TupleHash has one item; ParallelHash borrows an eight-byte leaf buffer.
use crate::Probe;

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
            /// 0 success, 1 API failure, 2 invalid fixture length, 3 vector mismatch.
            /// The optional known-answer check uses only synthetic non-secret values.
            #[inline(never)]
            fn $run(input: &[u8; 256], output: &mut [u8; 64], length: usize, expected: Option<&[u8]>) -> u8 {
                let Some(message) = input.get(..length) else { return 2; };
                let mut workspace = <$workspace>::new();
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
                $run(input, output, length, None)
            }
        )+
        /// Identical synthetic-input observer ABI; every owned output is 32 bytes.
        pub const PROBES: [(&str, Probe, usize); 12] = [$( (stringify!($name), $name, 32) ),+];
        /// Uses the actual probe worker before it drops its output owner.
        pub fn check_known(name: &str, input: &[u8;256], output: &mut [u8;64], length: usize, expected: &[u8]) -> u8 {
            match name { $( stringify!($name) => $run(input, output, length, Some(expected)), )+ _ => 2 }
        }
    };
}
probes!(
    (
        kmac128,
        run_kmac128,
        brynja_mac_kmac::hardened_in_place::Kmac128Workspace,
        kmac,
        fixed
    ),
    (
        kmac256,
        run_kmac256,
        brynja_mac_kmac::hardened_in_place::Kmac256Workspace,
        kmac,
        fixed
    ),
    (
        kmacxof128,
        run_kmacxof128,
        brynja_mac_kmac::hardened_in_place::KmacXof128Workspace,
        kmac,
        xof
    ),
    (
        kmacxof256,
        run_kmacxof256,
        brynja_mac_kmac::hardened_in_place::KmacXof256Workspace,
        kmac,
        xof
    ),
    (
        tuple128,
        run_tuple128,
        brynja_hash_tuple::hardened_in_place::TupleHash128Workspace,
        tuple,
        fixed
    ),
    (
        tuple256,
        run_tuple256,
        brynja_hash_tuple::hardened_in_place::TupleHash256Workspace,
        tuple,
        fixed
    ),
    (
        tuplexof128,
        run_tuplexof128,
        brynja_hash_tuple::hardened_in_place::TupleHashXof128Workspace,
        tuple,
        xof
    ),
    (
        tuplexof256,
        run_tuplexof256,
        brynja_hash_tuple::hardened_in_place::TupleHashXof256Workspace,
        tuple,
        xof
    ),
    (
        parallel128,
        run_parallel128,
        brynja_hash_parallel::hardened_in_place::ParallelHash128Workspace,
        parallel,
        fixed
    ),
    (
        parallel256,
        run_parallel256,
        brynja_hash_parallel::hardened_in_place::ParallelHash256Workspace,
        parallel,
        fixed
    ),
    (
        parallelxof128,
        run_parallelxof128,
        brynja_hash_parallel::hardened_in_place::ParallelHashXof128Workspace,
        parallel,
        xof
    ),
    (
        parallelxof256,
        run_parallelxof256,
        brynja_hash_parallel::hardened_in_place::ParallelHashXof256Workspace,
        parallel,
        xof
    ),
);
