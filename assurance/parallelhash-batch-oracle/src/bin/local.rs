//! Public vectors through scheduled/streaming hardened batching; no threads.
use brynja_hash_parallel::{
    Fips202BitString, ParallelHashPublicDeclassification as Public,
    execution::{Collector, Identity, Mode as RootMode, Plan, StreamConfig, WorkerPolicy, batch},
};
use brynja_hash_parallel_std::execution::Request;
use std::{
    fmt::Write as _,
    io::{self, Read as _},
};
#[path = "../request.rs"]
mod request;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn check<T, E: core::fmt::Debug>(result: std::result::Result<T, E>) -> Result<T> {
    result.map_err(|error| format!("{error:?}").into())
}

fn is_xof(identity: Identity) -> bool {
    matches!(
        identity,
        Identity::ParallelHashXof128 | Identity::ParallelHashXof256
    )
}

fn scheduled(
    request: &Request<'_>,
    executor: &batch::Executor<'_>,
    output: &mut [u8],
    valid: u8,
    public: bool,
) -> Result<u64> {
    let plan = check(Plan::new_bits(
        request.identity,
        request.input,
        request.block_size,
        4096,
    ))?;
    let mut root = check(Collector::new_bits(
        &plan,
        RootMode::Portable,
        request.customization,
    ))?;
    let mut workspace = batch::Workspace::new();
    let mut cancel = || false;
    let report = check(root.execute_batched(
        executor,
        &mut workspace,
        &mut batch::Control::new(32768, &mut cancel),
    ))?;
    let accelerated = check(executor.kernel())?.map_or(0, |k| {
        plan.leaf_count() / k.width() as u128 * k.width() as u128
    });
    if report.leaves != plan.leaf_count()
        || report.accelerated_leaves != accelerated
        || report.scalar_leaves.checked_add(report.accelerated_leaves) != Some(report.leaves)
        || root.merged_leaves() != plan.leaf_count()
        || root.accelerated_leaves() != accelerated
    {
        return Err("scheduled leaf accounting".into());
    }
    if public {
        let mut scratch = vec![0x5a; output.len() + 7];
        if is_xof(request.identity) {
            check(check(root.finalize_xof())?.squeeze_final_public(
                output,
                valid,
                &mut scratch,
                Public::acknowledge(),
            ))?;
        } else {
            check(root.finalize_public_bits(output, valid, &mut scratch, Public::acknowledge()))?;
        }
        if scratch.iter().any(|byte| *byte != 0) {
            return Err("scheduled scratch cleanup".into());
        }
    } else {
        let mut bytes = vec![0xa5; output.len() + 1];
        let size = output.len();
        let owned = if is_xof(request.identity) {
            check(check(root.finalize_xof())?.squeeze_final_secret(&mut bytes[..size], valid))?
        } else {
            check(root.finalize_secret_bits(&mut bytes[..size], valid))?
        };
        // This fixture's input is public generated data; this copy is intentional.
        output.copy_from_slice(owned.expose());
        drop(owned);
        if bytes[..size].iter().any(|byte| *byte != 0) || bytes.last() != Some(&0xa5) {
            return Err("scheduled secret Drop/canary cleanup".into());
        }
    }
    Ok(report.vector_calls)
}

fn streaming(
    request: &Request<'_>,
    executor: &batch::Executor<'_>,
    output: &mut [u8],
    valid: u8,
    public: bool,
    style: &str,
) -> Result<()> {
    let config = StreamConfig {
        identity: request.identity,
        max_leaves: 4096,
        workers: WorkerPolicy::Mixed,
    };
    let mut storage = vec![0xa5; request.block_size.checked_mul(4).ok_or("workspace bound")?];
    let mut stream = check(batch::Stream::new_bits(
        config,
        request.block_size,
        RootMode::Portable,
        executor,
        &mut storage,
        request.customization,
    ))?;
    let mut cancel = || false;
    let mut control = batch::Control::new(32768, &mut cancel);
    let bytes = request.input.as_bytes();
    let prefix = if style == "stream-tail" {
        0
    } else {
        bytes.len().saturating_sub(1)
    };
    let chunk = if style == "stream-byte" {
        1
    } else {
        request.block_size + 1
    };
    check(stream.update(&[], &mut control))?;
    for part in bytes[..prefix].chunks(chunk) {
        check(stream.update(part, &mut control))?;
        check(stream.update(&[], &mut control))?;
    }
    let merged = prefix / (4 * request.block_size) * 4;
    if stream.input_bits() != (prefix as u128) * 8 || stream.merged_leaves() != merged as u128 {
        return Err("stream prefix accounting".into());
    }
    let tail = check(Fips202BitString::new(
        &bytes[prefix..],
        request.input.valid_bits_in_last_byte(),
    ))?;
    let mut scratch = vec![0x5a; output.len() + 7];
    let mut secret = vec![0xa5; output.len() + 1];
    let size = output.len();
    if is_xof(request.identity) {
        let reader = check(stream.finalize_xof_bits(tail, &mut control))?;
        let leaves = bytes.len().div_ceil(request.block_size) as u128;
        let accelerated =
            check(executor.kernel())?.map_or(0, |k| leaves / k.width() as u128 * k.width() as u128);
        if reader.merged_leaves() != leaves || reader.accelerated_leaves() != accelerated {
            return Err("stream final leaf accounting".into());
        }
        if public {
            check(reader.squeeze_final_public(output, valid, &mut scratch, Public::acknowledge()))?;
        } else {
            let owned = check(reader.squeeze_final_secret(&mut secret[..size], valid))?;
            output.copy_from_slice(owned.expose());
            drop(owned);
        }
        if stream.update(b"x", &mut control).is_ok() {
            return Err("stream reopened after XOF".into());
        }
        drop(stream);
    } else if public {
        check(stream.finalize_public_bits(
            tail,
            output,
            valid,
            &mut scratch,
            Public::acknowledge(),
            &mut control,
        ))?;
    } else {
        let owned =
            check(stream.finalize_secret_bits(tail, &mut secret[..size], valid, &mut control))?;
        output.copy_from_slice(owned.expose());
        drop(owned);
    }
    if storage.iter().any(|byte| *byte != 0) {
        return Err("stream pending storage cleanup".into());
    }
    if public && scratch.iter().any(|byte| *byte != 0) {
        return Err("stream scratch cleanup".into());
    }
    if !public && (secret[..size].iter().any(|byte| *byte != 0) || secret.last() != Some(&0xa5)) {
        return Err("stream secret Drop/canary cleanup".into());
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("expected mode and scheduled|stream-byte|stream-block|stream-tail".into());
    }
    let mode = match args[0].as_str() {
        "portable" => batch::Mode::Portable,
        "prefer" => batch::Mode::Prefer,
        "required" => batch::Mode::Require,
        _ => return Err("unknown mode".into()),
    };
    let style = args[1].as_str();
    if !["scheduled", "stream-byte", "stream-block", "stream-tail"].contains(&style) {
        return Err("unknown layout".into());
    }
    let owner = if mode == batch::Mode::Portable {
        None
    } else {
        let kernel = if cfg!(target_arch = "aarch64") {
            batch::Kernel::Neon
        } else {
            batch::Kernel::Avx2
        };
        Some(check(batch::Authority::for_compiled_target(kernel))?)
    };
    let monitor = owner
        .as_ref()
        .map(|owner| owner.session())
        .transpose()
        .map_err(|e| format!("monitor: {e:?}"))?;
    let executor = if let Some(owner) = &owner {
        check(batch::Executor::with_session(
            check(owner.session())?,
            mode,
            1,
        ))?
    } else {
        batch::Executor::portable()
    };
    let calls = || {
        monitor
            .as_ref()
            .map_or(0, |session| session.completed_vector_calls())
    };
    let mut campaign = String::new();
    io::stdin().take(1_048_577).read_to_string(&mut campaign)?;
    if campaign.len() > 1_048_576 {
        return Err("campaign bound".into());
    }
    let mut rendered = String::new();
    let mut count = 0_usize;
    let mut total_vector = 0_u64;
    for line in campaign.lines() {
        count = count.checked_add(1).ok_or("case count")?;
        if count > 512 || line.len() > 17000 {
            return Err("case bound".into());
        }
        let case = request::Case::parse(line)?;
        let request = case.request()?;
        let size = case.output_bits.div_ceil(8);
        let valid = request::valid(case.output_bits)?;
        let mut public = vec![0xa5; size + 1];
        let mut secret_result = vec![0xa5; size + 1];
        let mut previous = None;
        for (is_public, output) in [(true, &mut public), (false, &mut secret_result)] {
            let before = calls();
            let reported = if style == "scheduled" {
                Some(scheduled(
                    &request,
                    &executor,
                    &mut output[..size],
                    valid,
                    is_public,
                )?)
            } else {
                streaming(
                    &request,
                    &executor,
                    &mut output[..size],
                    valid,
                    is_public,
                    style,
                )?;
                None
            };
            let actual = calls()
                .checked_sub(before)
                .ok_or("vector observation underflow")?;
            let accelerated = check(executor.kernel())?.is_some_and(|k| case.leaves() >= k.width());
            if (actual > 0) != accelerated
                || reported.is_some_and(|report| report != actual)
                || previous.is_some_and(|value| value != actual)
            {
                return Err("actual vector accounting".into());
            }
            previous = Some(actual);
            total_vector = total_vector
                .checked_add(actual)
                .ok_or("vector counter overflow")?;
            if output.last() != Some(&0xa5) {
                return Err("output canary".into());
            }
        }
        if public != secret_result {
            return Err("public/secret mismatch".into());
        }
        for byte in &public[..size] {
            write!(rendered, "{byte:02x}")?;
        }
        rendered.push('\n');
    }
    print!("{rendered}");
    eprintln!(
        "PARALLELHASH_LOCAL_ORACLE: cases={count}; vector_calls={total_vector}; layout={style}; profiles=public,secret; cleanup=drop,scratch,stream"
    );
    Ok(())
}
