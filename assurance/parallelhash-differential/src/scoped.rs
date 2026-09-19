use brynja_hash_parallel::{
    Fips202BitString, ParallelHashPublicDeclassification as Public, hardened_in_place as api,
};
use std::io;

pub(super) fn check(
    algorithm: &str,
    custom: Fips202BitString<'_>,
    input: Fips202BitString<'_>,
    valid: u8,
    b: usize,
    expected: &[u8],
) -> Result<(), io::Error> {
    let bad = |error| io::Error::other(format!("scoped ParallelHash rejected: {error:?}"));
    macro_rules! check {
        ($workspace:ident) => {{
            let mut workspace = api::$workspace::new();
            let mut block = vec![0xa5; b];
            let mut output = vec![0xa5; expected.len()];
            workspace
                .with_bits(&mut block, custom, |state| {
                    state.finalize_bits_public(input, &mut output, valid, Public::acknowledge())
                })
                .map_err(bad)?
                .map_err(bad)?;
            if output != expected || block.iter().any(|byte| *byte != 0) {
                return Err(io::Error::other("scoped public output/block mismatch"));
            }
            output.fill(0xa5);
            let secret = workspace
                .with_bits(&mut block, custom, |mut state| {
                    let complete = if input.is_byte_aligned() {
                        input.as_bytes().len()
                    } else {
                        input.as_bytes().len().saturating_sub(1)
                    };
                    for chunk in input.as_bytes()[..complete].chunks(13) {
                        state.update(chunk)?;
                    }
                    let tail = Fips202BitString::new(
                        &input.as_bytes()[complete..],
                        if input.is_byte_aligned() {
                            0
                        } else {
                            input.valid_bits_in_last_byte()
                        },
                    )
                    .map_err(|_| brynja_hash_parallel::ParallelHashError::InvalidBitString)?;
                    state.finalize_bits_secret(tail, &mut output, valid)
                })
                .map_err(bad)?
                .map_err(bad)?;
            if secret.expose() != expected {
                return Err(io::Error::other("scoped secret output mismatch"));
            }
            drop(secret);
            if output.iter().chain(&block).any(|byte| *byte != 0) {
                return Err(io::Error::other("scoped output/block not cleared"));
            }
        }};
    }
    match algorithm {
        "parallel128" => check!(ParallelHash128Workspace),
        "parallel256" => check!(ParallelHash256Workspace),
        "parallelxof128" | "parallelxof256" => (),
        _ => return Err(io::Error::other("unknown scoped identity")),
    }
    Ok(())
}
