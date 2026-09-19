use brynja_hash_parallel_std::{
    CancellationToken,
    execution::{Config, Preference, Request, in_place::Executor},
};
use std::io;

pub(super) fn check(
    request: &Request<'_>,
    preference: Preference,
    valid: u8,
    expected: &[u8],
) -> Result<(), io::Error> {
    let reject = |e| io::Error::other(format!("scoped threaded execution: {e:?}"));
    let executor = Executor::new(Config {
        workers: 3,
        max_leaves: 4096,
        root: preference,
        leaves: preference,
    })
    .map_err(reject)?;
    let token = CancellationToken::new();
    let mut output = vec![0xa5; expected.len()];
    let mut scratch = vec![0xa5; expected.len()];
    let report = executor
        .hash_public_bits(request, &mut output, valid, &mut scratch, &token)
        .map_err(reject)?;
    if output != expected || scratch.iter().any(|b| *b != 0) {
        return Err(io::Error::other("scoped threaded public mismatch"));
    }
    let (secret, secret_report) = executor
        .hash_secret_bits(request, &mut output, valid, &token)
        .map_err(reject)?;
    if secret.expose() != expected || secret_report.leaves != report.leaves {
        return Err(io::Error::other("scoped threaded secret mismatch"));
    }
    if matches!(preference, Preference::Require | Preference::RequireStatic)
        && (report.root.is_none()
            || report.accelerated_leaves != report.leaves
            || secret_report.root.is_none()
            || secret_report.accelerated_leaves != secret_report.leaves)
    {
        return Err(io::Error::other("scoped threaded required route mismatch"));
    }
    drop(secret);
    if output.iter().any(|b| *b != 0) {
        return Err(io::Error::other("scoped threaded secret cleanup"));
    }
    Ok(())
}
