//! Cross-check scoped multibuffer plan/output ownership against the oracle.
use super::{Request, Result, check, is_xof};
use brynja_hash_parallel::{self as hash, execution::batch, hardened_in_place as root};

pub(super) fn compare(
    request: &Request<'_>,
    executor: &batch::Executor<'_>,
    expected: &[u8],
    valid: u8,
) -> Result<u64> {
    macro_rules! run {
        ($plan:ident, $workspace:ident) => {{
            let plan = check(hash::$plan::new_bits(request.input, request.block_size))?;
            let mut workspace = root::$workspace::new();
            check(
                workspace.with_bits(&plan, request.customization, |mut root| -> Result<u64> {
                    let mut leaf = batch::Workspace::new();
                    let mut slots = [[0xa5; 64]; 4];
                    let mut start = 0u128;
                    let mut calls = 0u64;
                    let mut accelerated = 0u128;
                    while start < plan.leaf_count() {
                        let count = usize::try_from(
                            plan.leaf_count()
                                .checked_sub(start)
                                .ok_or("leaf remainder")?
                                .min(4),
                        )?;
                        let mut no = || false;
                        let result = check(check(plan.batch(start, count))?.execute_into(
                            executor,
                            &mut leaf,
                            &mut slots,
                            &mut batch::Control::new(32768, &mut no),
                        ))?;
                        let report = result.report();
                        calls = calls
                            .checked_add(report.vector_calls)
                            .ok_or("vector overflow")?;
                        accelerated = accelerated
                            .checked_add(u128::from(report.accelerated_slots.count_ones()))
                            .ok_or("leaf overflow")?;
                        check(root.merge_batch(result))?;
                        if slots.iter().flatten().any(|b| *b != 0) {
                            return Err("scoped group clearing".into());
                        }
                        start = start.checked_add(count as u128).ok_or("index overflow")?;
                    }
                    let wanted = match check(executor.kernel())? {
                        Some(k) => plan
                            .leaf_count()
                            .checked_div(k.width() as u128)
                            .and_then(|n| n.checked_mul(k.width() as u128))
                            .ok_or("route arithmetic")?,
                        None => 0,
                    };
                    if accelerated != wanted {
                        return Err("scoped group route accounting".into());
                    }
                    let mut output = vec![0xa5; expected.len()];
                    let secret = if is_xof(request.identity) {
                        check(
                            check(root.finalize_xof())?
                                .squeeze_final_bits_secret(&mut output, valid),
                        )?
                    } else {
                        check(root.finalize_secret_bits(&mut output, valid))?
                    };
                    if secret.expose() != expected {
                        return Err("scoped batch oracle mismatch".into());
                    }
                    drop(secret);
                    if output.iter().any(|b| *b != 0) {
                        return Err("scoped secret clearing".into());
                    }
                    Ok(calls)
                }),
            )?
        }};
    }
    match request.identity {
        hash::execution::Identity::ParallelHash128
        | hash::execution::Identity::ParallelHashXof128 => {
            run!(ParallelHash128Plan, ParallelHash128CollectorWorkspace)
        }
        _ => run!(ParallelHash256Plan, ParallelHash256CollectorWorkspace),
    }
}
