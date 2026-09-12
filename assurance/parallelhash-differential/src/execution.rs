use brynja_crypto_cpu::{hardened_execution::KeccakSession, static_execution::Kernel};
use brynja_crypto_cpu_std::execution::{Authority, Mode as Hosted};
use brynja_hash_parallel::{
    Fips202BitString, ParallelHashPublicDeclassification as Public,
    execution::{Collector, Error, Identity, Mode, Plan, Stream, StreamConfig, WorkerPolicy},
};
use brynja_hash_parallel_std::{
    CancellationToken,
    execution::{Config, Executor, Preference, Request},
};
use std::io;

pub(super) fn run(
    algorithm: &str,
    custom: Fips202BitString<'_>,
    input: Fips202BitString<'_>,
    output_bits: usize,
    block: usize,
    output: &mut [u8],
    line: usize,
) -> Result<(), io::Error> {
    let reject = |_| super::invalid(line, "execution rejected");
    let identity = match algorithm {
        "parallel128" => Identity::ParallelHash128,
        "parallel256" => Identity::ParallelHash256,
        "parallelxof128" => Identity::ParallelHashXof128,
        "parallelxof256" => Identity::ParallelHashXof256,
        _ => return Err(super::invalid(line, "unknown identity")),
    };
    let route = std::env::args()
        .nth(1)
        .ok_or_else(|| super::invalid(line, "missing route"))?;
    let mut scratch = super::bounded_vec(output.len(), line, "scratch allocation failed")?;
    let valid = super::valid_bits(output_bits);
    if let Some(preference) = match route.as_str() {
        "threads-portable" => Some(Preference::Portable),
        "threads-prefer" => Some(Preference::Prefer),
        "threads-required" => Some(Preference::Require),
        "threads-static" => Some(Preference::RequireStatic),
        _ => None,
    } {
        let executor = Executor::new(Config {
            workers: 3,
            max_leaves: 4096,
            root: preference,
            leaves: preference,
        })
        .map_err(|_| super::invalid(line, "executor limits"))?;
        let request = Request {
            identity,
            input,
            block_size: block,
            customization: custom,
        };
        let report = executor
            .hash_public_bits(
                &request,
                output,
                valid,
                &mut scratch,
                &CancellationToken::new(),
            )
            .map_err(|_| super::invalid(line, "threaded execution rejected"))?;
        if matches!(preference, Preference::Require | Preference::RequireStatic)
            && (report.root.is_none() || report.accelerated_leaves != report.leaves)
        {
            return Err(super::invalid(line, "threaded execution route mismatch"));
        }
        return Ok(());
    }
    let kernel = if cfg!(target_arch = "x86_64") {
        Kernel::X86Keccak
    } else {
        Kernel::ArmKeccak
    };
    let owner = match route.as_str() {
        "portable" | "scheduled" | "stream" | "static" | "stream-static" => None,
        "prefer" | "stream-prefer" => Some(
            Authority::new(kernel, Hosted::Prefer)
                .map_err(|_| super::invalid(line, "hosted detection"))?,
        ),
        "required" | "stream-required" => Some(
            Authority::new(kernel, Hosted::Require)
                .map_err(|_| super::invalid(line, "required authority unavailable"))?,
        ),
        _ => return Err(super::invalid(line, "unknown route")),
    };
    let specialized = if matches!(route.as_str(), "static" | "stream-static") {
        Some(
            brynja_crypto_cpu::static_execution::Authority::new(kernel)
                .map_err(|_| super::invalid(line, "static authority unavailable"))?,
        )
    } else {
        None
    };
    let select = || -> Result<Mode<'_>, Error> {
        if let Some(owner) = &specialized {
            return Ok(Mode::Require(Some(
                KeccakSession::from_static(owner).map_err(|_| Error::State)?,
            )));
        }
        match &owner {
            None => Ok(Mode::Portable),
            Some(owner) => match owner.session().map_err(|_| Error::State)? {
                None => Ok(Mode::Prefer(None)),
                Some(session) => Ok(Mode::Require(Some(
                    KeccakSession::from_runtime(session).map_err(|_| Error::State)?,
                ))),
            },
        }
    };
    if route.starts_with("stream") {
        let required = matches!(route.as_str(), "stream-required" | "stream-static");
        let mut workspace = super::bounded_vec(block, line, "stream workspace allocation failed")?;
        let mut stream = Stream::new_bits(
            StreamConfig {
                identity,
                max_leaves: 4096,
                workers: if required {
                    WorkerPolicy::RequireAcceleration
                } else {
                    WorkerPolicy::Mixed
                },
            },
            select().map_err(reject)?,
            &mut workspace,
            custom,
        )
        .map_err(reject)?;
        if required && stream.report().is_none() {
            return Err(super::invalid(line, "missing stream root route"));
        }
        let (prefix, tail) = if input.is_byte_aligned() {
            (input.as_bytes(), super::bit_string(&[], 0, line)?)
        } else {
            let (last, prefix) = input
                .as_bytes()
                .split_last()
                .ok_or_else(|| super::invalid(line, "missing input tail"))?;
            (
                prefix,
                Fips202BitString::new(core::slice::from_ref(last), input.valid_bits_in_last_byte())
                    .map_err(|_| super::invalid(line, "invalid input tail"))?,
            )
        };
        for chunk in prefix.chunks(7) {
            stream.update(chunk, |_| select()).map_err(reject)?;
        }
        if matches!(
            identity,
            Identity::ParallelHashXof128 | Identity::ParallelHashXof256
        ) {
            stream
                .finalize_xof_bits(tail, |_| select())
                .map_err(reject)?
                .squeeze_final_public(output, valid, &mut scratch, Public::acknowledge())
                .map_err(reject)?;
        } else {
            stream
                .finalize_public_bits(
                    tail,
                    output,
                    valid,
                    &mut scratch,
                    Public::acknowledge(),
                    |_| select(),
                )
                .map_err(reject)?;
        }
        return Ok(());
    }
    let plan = Plan::new_bits(identity, input, block, 4096).map_err(reject)?;
    let mut root = Collector::new_bits(&plan, select().map_err(reject)?, custom).map_err(reject)?;
    if route == "scheduled" {
        let mut slot = [0xa5; 64];
        for index in 0..plan.leaf_count() {
            let bytes = slot
                .get_mut(..identity.leaf_bytes())
                .ok_or_else(|| super::invalid(line, "leaf width"))?;
            let leaf = plan
                .job(index)
                .map_err(reject)?
                .execute(select().map_err(reject)?, bytes)
                .map_err(reject)?;
            root.merge(&leaf).map_err(reject)?;
        }
    } else {
        root.execute_serial(|_| select()).map_err(reject)?;
    }
    if matches!(route.as_str(), "required" | "static")
        && (root.report().is_none() || root.accelerated_leaves() != plan.leaf_count())
    {
        return Err(super::invalid(line, "execution route mismatch"));
    }
    if matches!(
        identity,
        Identity::ParallelHashXof128 | Identity::ParallelHashXof256
    ) {
        root.finalize_xof()
            .map_err(reject)?
            .squeeze_final_public(output, valid, &mut scratch, Public::acknowledge())
            .map_err(reject)
    } else {
        root.finalize_public_bits(output, valid, &mut scratch, Public::acknowledge())
            .map_err(reject)
    }
}
