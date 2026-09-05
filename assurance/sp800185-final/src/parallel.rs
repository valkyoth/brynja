use brynja_hash_parallel::{
    Fips202BitString, Fips202Output, ParallelHash128, ParallelHash128Collector,
    ParallelHash128Plan, ParallelHash256, ParallelHash256Collector, ParallelHash256Plan,
    ParallelHashError, ParallelHashPublicDeclassification, ParallelHashXof128, ParallelHashXof256,
    parallel_hash_xof128, parallel_hash_xof256, parallel_hash128, parallel_hash256,
};
use brynja_hash_parallel_std::{
    CancellationToken, ParallelHashExecutor, ParallelHashExecutorError,
};

use crate::Error;

const CUSTOM: &[u8] = b"final-acceptance";
const OUTPUT: usize = 37;

macro_rules! byte_case {
    ($executor:expr, $input:expr, $block:expr, $function:ident) => {{
        let mut workspace = [0_u8; 127];
        let mut expected = [0_u8; OUTPUT];
        $function($input, &mut workspace[..$block], CUSTOM, &mut expected)
            .map_err(|_| Error::Parallel)?;
        let mut actual = [0xa5_u8; OUTPUT];
        $executor
            .$function(
                $input,
                $block,
                CUSTOM,
                &mut actual,
                &CancellationToken::new(),
            )
            .map_err(|_| Error::Parallel)?;
        if actual != expected {
            return Err(Error::Parallel);
        }
    }};
}

macro_rules! bit_case {
    ($executor:expr, $input:expr, $block:expr, $state:ident, $method:ident, $xof:tt) => {{
        let length = $input.len();
        let mut canonical = [0_u8; 137];
        canonical[..length].copy_from_slice($input);
        let tail_width = if length == 0 { 0 } else { 5 };
        if let Some(last) = canonical[..length].last_mut() { *last &= 0x1f; }
        let input = Fips202BitString::new(&canonical[..length], tail_width)
            .map_err(|_| Error::Parallel)?;
        let custom = Fips202BitString::new(&[0x15], 5).map_err(|_| Error::Parallel)?;
        let mut workspace = [0_u8; 127];
        let mut state = $state::new_bits(&mut workspace[..$block], custom)
            .map_err(|_| Error::Parallel)?;
        let mut expected = [0_u8; OUTPUT];
        bit_case!(@finish state, input, expected, $xof);
        let mut actual = [0xa5_u8; OUTPUT];
        $executor.$method(input, $block, custom,
            Fips202Output::new(&mut actual, 3).map_err(|_| Error::Parallel)?,
            &CancellationToken::new()).map_err(|_| Error::Parallel)?;
        if actual != expected { return Err(Error::Parallel); }
    }};
    (@finish $state:ident, $input:ident, $output:ident, false) => {
        $state.finalize_bits($input, Fips202Output::new(&mut $output, 3)
            .map_err(|_| Error::Parallel)?).map_err(|_| Error::Parallel)?;
    };
    (@finish $state:ident, $input:ident, $output:ident, true) => {
        $state.finalize_bits_xof($input).map_err(|_| Error::Parallel)?
            .squeeze_final_bits(Fips202Output::new(&mut $output, 3)
                .map_err(|_| Error::Parallel)?).map_err(|_| Error::Parallel)?;
    };
}

pub(crate) fn compare() -> Result<usize, Error> {
    let input: [u8; 137] = core::array::from_fn(|i| u8::try_from(i).unwrap_or_default());
    let mut cases = 0;
    for length in [0, 1, 17, 65, 137] {
        for workers in [1, 2, 4] {
            let executor = ParallelHashExecutor::new(workers, 256).map_err(|_| Error::Parallel)?;
            for block in [8, 32, 127] {
                let message = &input[..length];
                byte_case!(executor, message, block, parallel_hash128);
                byte_case!(executor, message, block, parallel_hash256);
                byte_case!(executor, message, block, parallel_hash_xof128);
                byte_case!(executor, message, block, parallel_hash_xof256);
                bit_case!(
                    executor,
                    message,
                    block,
                    ParallelHash128,
                    parallel_hash128_bits,
                    false
                );
                bit_case!(
                    executor,
                    message,
                    block,
                    ParallelHash256,
                    parallel_hash256_bits,
                    false
                );
                bit_case!(
                    executor,
                    message,
                    block,
                    ParallelHashXof128,
                    parallel_hash_xof128_bits,
                    true
                );
                bit_case!(
                    executor,
                    message,
                    block,
                    ParallelHashXof256,
                    parallel_hash_xof256_bits,
                    true
                );
                scheduled(message, block)?;
                cases += 12;
            }
        }
    }
    Ok(cases)
}

// Ordered public collection consumes every leaf once, comparing before erasure.
fn scheduled(input: &[u8], block: usize) -> Result<(), Error> {
    macro_rules! check {
        ($plan:ident, $collector:ident, $size:literal, $hash:ident, $xof:ident) => {{
            for is_xof in [false, true] {
                let plan = $plan::new(input, block).map_err(|_| Error::Parallel)?;
                let mut collector = $collector::new(&plan, CUSTOM).map_err(|_| Error::Parallel)?;
                for index in 0..plan.leaf_count() {
                    let mut storage = [0_u8; $size];
                    let result = plan
                        .job(index)
                        .map_err(|_| Error::Parallel)?
                        .execute(&mut storage)
                        .map_err(|_| Error::Parallel)?;
                    collector.merge(&result).map_err(|_| Error::Parallel)?;
                    drop(result);
                    if storage != [0; $size] {
                        return Err(Error::Parallel);
                    }
                }
                let mut actual = [0_u8; OUTPUT];
                let mut expected = [0_u8; OUTPUT];
                let mut workspace = [0_u8; 127];
                if is_xof {
                    collector
                        .finalize_xof()
                        .map_err(|_| Error::Parallel)?
                        .squeeze_public(
                            &mut actual,
                            ParallelHashPublicDeclassification::acknowledge(),
                        )
                        .map_err(|_| Error::Parallel)?;
                    $xof(input, &mut workspace[..block], CUSTOM, &mut expected)
                        .map_err(|_| Error::Parallel)?;
                } else {
                    collector
                        .finalize(&mut actual)
                        .map_err(|_| Error::Parallel)?;
                    $hash(input, &mut workspace[..block], CUSTOM, &mut expected)
                        .map_err(|_| Error::Parallel)?;
                }
                if actual != expected {
                    return Err(Error::Parallel);
                }
            }
        }};
    }
    check!(
        ParallelHash128Plan,
        ParallelHash128Collector,
        32,
        parallel_hash128,
        parallel_hash_xof128
    );
    check!(
        ParallelHash256Plan,
        ParallelHash256Collector,
        64,
        parallel_hash256,
        parallel_hash_xof256
    );
    Ok(())
}

pub(crate) fn failures() -> Result<usize, Error> {
    let mut cases = 0;
    let executor = ParallelHashExecutor::new(2, 1).map_err(|_| Error::Failure)?;
    for mode in 0..3 {
        let cancellation = CancellationToken::new();
        let (input, block) = match mode {
            0 => {
                cancellation.cancel();
                (&b""[..], 1)
            }
            1 => (&b"two leaves"[..], 1),
            _ => (&b""[..], 0),
        };
        macro_rules! verify {
            ($result:expr, $output:ident) => {{
                let accepted_error = match (mode, $result) {
                    (0, Err(ParallelHashExecutorError::Cancelled))
                    | (1, Err(ParallelHashExecutorError::WorkLimitExceeded))
                    | (
                        2,
                        Err(ParallelHashExecutorError::Construction(
                            ParallelHashError::InvalidBlockSize,
                        )),
                    ) => true,
                    _ => false,
                };
                if !accepted_error || $output != [0xa5; OUTPUT] {
                    return Err(Error::Failure);
                }
                cases += 1;
            }};
        }
        macro_rules! byte {
            ($method:ident) => {{
                let mut output = [0xa5; OUTPUT];
                verify!(
                    executor.$method(input, block, CUSTOM, &mut output, &cancellation),
                    output
                );
            }};
        }
        macro_rules! bit {
            ($method:ident) => {{
                let mut output = [0xa5; OUTPUT];
                let bits = Fips202BitString::new(input, if input.is_empty() { 0 } else { 8 })
                    .map_err(|_| Error::Failure)?;
                let custom = Fips202BitString::new(&[], 0).map_err(|_| Error::Failure)?;
                let out = Fips202Output::new(&mut output, 3).map_err(|_| Error::Failure)?;
                verify!(
                    executor.$method(bits, block, custom, out, &cancellation),
                    output
                );
            }};
        }
        byte!(parallel_hash128);
        byte!(parallel_hash256);
        byte!(parallel_hash_xof128);
        byte!(parallel_hash_xof256);
        bit!(parallel_hash128_bits);
        bit!(parallel_hash256_bits);
        bit!(parallel_hash_xof128_bits);
        bit!(parallel_hash_xof256_bits);
    }
    Ok(cases)
}
