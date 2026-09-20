//! Coordinator return diagnostics, NOT observations of exited workers' registers.
use crate::Probe;
use brynja_hash_parallel::{Fips202BitString, execution::Identity};
use brynja_hash_parallel_std::{CancellationToken, execution as api};

#[derive(Clone, Copy, PartialEq)]
pub enum Route {
    Portable,
    Static,
    Batch,
}

pub fn checked_report(report: api::Report, route: Route, leaves: usize) -> bool {
    let jobs = if route == Route::Batch {
        leaves.div_ceil(4)
    } else {
        leaves
    };
    let accelerated = if route == Route::Portable {
        0
    } else {
        leaves as u128
    };
    report.leaves == leaves as u128
        && report.accelerated_leaves == accelerated
        && report.thread_width == jobs.min(2)
        && if route == Route::Portable {
            report.root.is_none()
        } else {
            report.root.is_some_and(crate::accelerated::valid)
        }
}

#[inline(never)]
fn run(
    identity: Identity,
    route: Route,
    input: &[u8; 256],
    output: &mut [u8; 64],
    length: usize,
    expected: Option<&[u8]>,
    cancel: bool,
) -> u8 {
    let Some(message) = input.get(..length) else {
        return 2;
    };
    let mut checked = || -> Result<u8, ()> {
        let token = CancellationToken::new();
        if cancel {
            token.cancel();
        }
        let request = api::Request {
            identity,
            input: Fips202BitString::new(message, if length == 0 { 0 } else { 8 })
                .map_err(|_| ())?,
            customization: Fips202BitString::new(&[], 0).map_err(|_| ())?,
            block_size: 8,
        };
        let leaves = length.div_ceil(8);
        let output_pointer = output.as_ptr();
        macro_rules! finish {
            ($secret:ident, $report:expr) => {{
                let status = if !checked_report($report, route, leaves)
                    || $secret.expose().as_ptr() != output_pointer
                {
                    4
                } else if expected.is_some_and(|bytes| bytes != $secret.expose()) {
                    3
                } else {
                    0
                };
                drop($secret);
                Ok(status)
            }};
        }
        if route == Route::Batch {
            let executor = api::batch::in_place::Executor::new(api::batch::Config {
                workers: 2,
                max_leaves: 32,
                root: api::Preference::RequireStatic,
                leaves: api::Preference::RequireStatic,
                minimum_permutations: 1,
                max_group_permutations: 64,
            })
            .map_err(|_| ())?;
            let (secret, report) = executor
                .hash_secret(&request, &mut output[..32], &token)
                .map_err(|_| ())?;
            // Eight-byte leaves require one SHAKE permutation each; complete
            // four-leaf groups avoid deliberately ineligible required-mode tails.
            let width = if cfg!(target_arch = "aarch64") { 2 } else { 4 };
            if report.groups != leaves.div_ceil(4) as u128
                || report.vector_calls != (leaves / width) as u64
                || report.vector_permutations != leaves as u64
                || report.scalar_permutations != 0
            {
                return Ok(4);
            }
            finish!(secret, report.execution)
        } else {
            let preference = if route == Route::Portable {
                api::Preference::Portable
            } else {
                api::Preference::RequireStatic
            };
            let executor = api::in_place::Executor::new(api::Config {
                workers: 2,
                max_leaves: 32,
                root: preference,
                leaves: preference,
            })
            .map_err(|_| ())?;
            let (secret, report) = executor
                .hash_secret(&request, &mut output[..32], &token)
                .map_err(|_| ())?;
            finish!(secret, report)
        }
    };
    checked().unwrap_or(1)
}

macro_rules! probes {
    ($(($name:ident, $identity:ident, $route:ident)),+ $(,)?) => {
        $(
            /// Synthetic-only coordinator call. Workers are joined before return.
            #[inline(never)]
            pub extern "C" fn $name(input: &[u8;256], output: &mut [u8;64], length: usize) -> u8 {
                run(Identity::$identity, Route::$route, input, output, length, None, false)
            }
        )+
        pub const PROBES: [(&str, Probe, usize); 12] = [$( (stringify!($name), $name, 32) ),+];
        /// Uses the actual probe worker, checking the digest before output Drop.
        pub fn check_known(name: &str, input: &[u8;256], output: &mut [u8;64], expected: &[u8]) -> u8 {
            match name { $(stringify!($name) => run(Identity::$identity, Route::$route, input, output, 128, Some(expected), false),)+ _ => 2 }
        }
        /// Pre-cancelled execution must clear its owned destination and reject.
        pub fn check_cancelled(name: &str, input: &[u8;256], output: &mut [u8;64]) -> u8 {
            match name { $(stringify!($name) => run(Identity::$identity, Route::$route, input, output, 128, None, true),)+ _ => 2 }
        }
    };
}
probes!(
    (portable128, ParallelHash128, Portable),
    (portable256, ParallelHash256, Portable),
    (portablexof128, ParallelHashXof128, Portable),
    (portablexof256, ParallelHashXof256, Portable),
    (static128, ParallelHash128, Static),
    (static256, ParallelHash256, Static),
    (staticxof128, ParallelHashXof128, Static),
    (staticxof256, ParallelHashXof256, Static),
    (batch128, ParallelHash128, Batch),
    (batch256, ParallelHash256, Batch),
    (batchxof128, ParallelHashXof128, Batch),
    (batchxof256, ParallelHashXof256, Batch),
);
