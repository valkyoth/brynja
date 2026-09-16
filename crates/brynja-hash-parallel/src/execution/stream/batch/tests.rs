use super::*;
use crate::execution::{Identity, WorkerPolicy};
use crate::{Fips202Output, ParallelHashPublicDeclassification as Public};
extern crate std;
use std::{vec, vec::Vec};

fn config(identity: Identity) -> StreamConfig {
    StreamConfig {
        identity,
        max_leaves: 32,
        workers: WorkerPolicy::Mixed,
    }
}
fn bits(bytes: &[u8], valid: u8) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bytes, valid).map_err(|_| RootError::State.into())
}
fn reference(
    identity: Identity,
    input: Fips202BitString<'_>,
    block: usize,
    custom: Fips202BitString<'_>,
    output: &mut [u8],
) -> Result<(), Error> {
    let mut workspace = vec![0; block];
    let output = Fips202Output::new(output, 5).map_err(|_| RootError::State)?;
    macro_rules! fixed {
        ($ty:ty) => {
            <$ty>::new_bits(&mut workspace, custom)
                .map_err(RootError::from)?
                .finalize_bits(input, output)
                .map_err(RootError::from)?
        };
    }
    macro_rules! xof {
        ($ty:ty) => {
            <$ty>::new_bits(&mut workspace, custom)
                .map_err(RootError::from)?
                .finalize_bits_xof(input)
                .map_err(RootError::from)?
                .squeeze_final_bits(output)
                .map_err(RootError::from)?
        };
    }
    match identity {
        Identity::ParallelHash128 => fixed!(crate::ParallelHash128<'_>),
        Identity::ParallelHash256 => fixed!(crate::ParallelHash256<'_>),
        Identity::ParallelHashXof128 => xof!(crate::ParallelHashXof128<'_>),
        Identity::ParallelHashXof256 => xof!(crate::ParallelHashXof256<'_>),
    }
    Ok(())
}
fn campaign(executor: &Executor<'_>) -> Result<(), Error> {
    for identity in [
        Identity::ParallelHash128,
        Identity::ParallelHash256,
        Identity::ParallelHashXof128,
        Identity::ParallelHashXof256,
    ] {
        for block in [1_usize, 7, 136, 168] {
            for length in [
                0,
                1,
                block,
                block.saturating_mul(4),
                block.saturating_mul(5).saturating_add(1),
                block.saturating_mul(9),
            ] {
                for valid in [1_u8, 8] {
                    let mut message: Vec<_> = (0..length)
                        .map(|i| i.to_le_bytes()[0].wrapping_mul(29))
                        .collect();
                    if let Some(last) = message.last_mut() {
                        *last &= 0xff_u8 >> 8_u8.saturating_sub(valid);
                    }
                    let input = bits(&message, if length == 0 { 0 } else { valid })?;
                    let custom = bits(&[19], 5)?;
                    let mut expected = [0; 193];
                    reference(identity, input, block, custom, &mut expected)?;
                    for chunk in [
                        1,
                        block.saturating_add(1),
                        block.saturating_mul(4).saturating_add(1),
                    ] {
                        let mut storage = vec![0xa5; block.saturating_mul(4)];
                        let mut stream = Stream::new_bits(
                            config(identity),
                            block,
                            Mode::Portable,
                            executor,
                            &mut storage,
                            custom,
                        )?;
                        let prefix = if chunk > block.saturating_mul(4) {
                            0
                        } else {
                            length.saturating_sub(1)
                        };
                        let mut no = || false;
                        let mut control = Control::new(256, &mut no);
                        for part in message.get(..prefix).ok_or(RootError::State)?.chunks(chunk) {
                            stream.update(part, &mut control)?;
                            stream.update(&[], &mut control)?;
                        }
                        let tail = bits(
                            message.get(prefix..).ok_or(RootError::State)?,
                            if length == 0 { 0 } else { valid },
                        )?;
                        let mut output = [0xa5; 193];
                        if identity.xof() {
                            let mut reader = stream.finalize_xof_bits(tail, &mut control)?;
                            let leaves = (length as u128).div_ceil(block as u128);
                            assert_eq!(reader.merged_leaves(), leaves);
                            let accelerated = executor.kernel()?.map_or(0, |k| {
                                leaves
                                    .checked_div(k.width() as u128)
                                    .and_then(|n| n.checked_mul(k.width() as u128))
                                    .unwrap_or(0)
                            });
                            assert_eq!(reader.accelerated_leaves(), accelerated);
                            let mut first = [0; 80];
                            let secret = reader.squeeze_secret(&mut first)?;
                            output[..80].copy_from_slice(secret.expose());
                            drop(secret);
                            assert_eq!(first, [0; 80]);
                            let mut stage = [0xa5; 64];
                            reader.squeeze_public(
                                &mut output[80..144],
                                &mut stage,
                                Public::acknowledge(),
                            )?;
                            assert_eq!(stage, [0; 64]);
                            let mut last_stage = [0xa5; 49];
                            reader.squeeze_final_public(
                                &mut output[144..],
                                5,
                                &mut last_stage,
                                Public::acknowledge(),
                            )?;
                            assert_eq!(last_stage, [0; 49]);
                            assert!(stream.update(b"x", &mut control).is_err());
                            drop(stream);
                            assert_eq!(output, expected);
                        } else {
                            let secret =
                                stream.finalize_secret_bits(tail, &mut output, 5, &mut control)?;
                            assert_eq!(secret.expose(), expected);
                            drop(secret);
                            assert_eq!(output, [0; 193]);
                        }
                        assert!(storage.iter().all(|v| *v == 0));
                    }
                }
            }
        }
    }
    Ok(())
}
#[test]
fn portable_chunk_bit_and_xof_campaign() -> Result<(), Error> {
    campaign(&Executor::portable())
}
#[test]
fn vector_chunk_bit_and_xof_campaign() -> Result<(), Error> {
    let kernel = if cfg!(target_arch = "aarch64") {
        batch::Kernel::Neon
    } else {
        batch::Kernel::Avx2
    };
    if !kernel.compiled() {
        assert!(std::env::var_os("BRYNJA_REQUIRE_PARALLELHASH_BATCH").is_none());
        return Ok(());
    }
    let owner = batch::Authority::for_compiled_target(kernel)
        .map_err(brynja_hash_sha3::hardened_batch::Error::Backend)?;
    campaign(&Executor::with_session(
        owner
            .session()
            .map_err(brynja_hash_sha3::hardened_batch::Error::Backend)?,
        batch::Mode::Prefer,
        1,
    )?)
}

fn cleared(stream: &Stream<'_, '_, '_>) {
    assert!(stream.workspace.iter().all(|v| *v == 0));
    assert_eq!(stream.used, [0; 16]);
    assert_eq!(stream.input_bits, [0; 16]);
    assert_eq!(stream.root.merged_leaves(), 0);
    assert!(!stream.root.absorbing());
}
#[test]
fn exact_completion_rejects_corrupted_pending_and_counts() -> Result<(), Error> {
    for corruption in 0..3 {
        for secret in [false, true] {
            let executor = Executor::portable();
            let mut storage = [0; 4];
            let mut stream = Stream::new(
                config(Identity::ParallelHash128),
                1,
                Mode::Portable,
                &executor,
                &mut storage,
                b"",
            )?;
            let mut no = || false;
            let mut control = Control::new(32, &mut no);
            stream.update(b"abcd", &mut control)?;
            if corruption == 0 {
                stream.input_bits = 40_u128.to_le_bytes();
            }
            if corruption == 1 {
                stream.input_bits = 24_u128.to_le_bytes();
            }
            if corruption == 2 {
                stream.used = 1_u128.to_le_bytes();
                *stream.workspace.get_mut(0).ok_or(RootError::State)? = 0xaa;
                assert!(stream.check_complete().is_err());
            }
            let mut out = [0xa5; 32];
            let mut scratch = [0xff; 32];
            if secret {
                assert!(stream.finalize_secret(&mut out, &mut control).is_err());
                assert_eq!(out, [0; 32]);
            } else {
                assert!(
                    stream
                        .finalize_public(
                            &mut out,
                            &mut scratch,
                            Public::acknowledge(),
                            &mut control
                        )
                        .is_err()
                );
                assert_eq!(out, [0xa5; 32]);
                assert_eq!(scratch, [0; 32]);
            }
            assert_eq!(storage, [0; 4]);
        }
    }
    Ok(())
}
#[test]
fn pending_stream_drop_clears_buffer() -> Result<(), Error> {
    let executor = Executor::portable();
    let mut pending = [0; 8];
    let mut stream = Stream::new(
        config(Identity::ParallelHash128),
        2,
        Mode::Portable,
        &executor,
        &mut pending,
        b"",
    )?;
    let mut no = || false;
    stream.update(b"secret", &mut Control::new(32, &mut no))?;
    assert_eq!(stream.used()?, 6);
    drop(stream);
    assert_eq!(pending, [0; 8]);
    Ok(())
}
#[test]
fn cancellation_budget_unwind_and_drop_clear_pending_storage() -> Result<(), Error> {
    pending_stream_drop_clears_buffer()?;
    for action in 0..3 {
        for boundary in 0_u64..18 {
            let executor = Executor::portable();
            let mut storage = [0xa5; 8];
            let mut stream = Stream::new(
                config(Identity::ParallelHash256),
                2,
                Mode::Portable,
                &executor,
                &mut storage,
                b"",
            )?;
            let mut no = || false;
            stream.update(b"abc", &mut Control::new(8, &mut no))?;
            let mut calls = 0_u64;
            let mut cancel = || {
                calls = calls.saturating_add(1);
                if action == 2 && calls == boundary {
                    std::panic::resume_unwind(std::boxed::Box::new(()));
                }
                action == 1 && calls == boundary
            };
            let mut control = Control::new(if action == 0 { boundary } else { 64 }, &mut cancel);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                stream.update(&[0x93; 13], &mut control)
            }));
            if !matches!(result, Ok(Ok(()))) {
                cleared(&stream);
                assert!(stream.update(&[], &mut Control::new(64, &mut no)).is_err());
            }
            drop(stream);
            assert_eq!(storage, [0; 8]);
        }
    }
    Ok(())
}
#[test]
fn construction_work_limit_cancellation_and_forgotten_reader() -> Result<(), Error> {
    let executor = Executor::portable();
    for (block, size) in [(0, 4), (2, 7), (usize::MAX, 4)] {
        let mut storage = vec![0xa5; size];
        assert!(
            Stream::new(
                config(Identity::ParallelHash128),
                block,
                Mode::Portable,
                &executor,
                &mut storage,
                b""
            )
            .is_err()
        );
        assert!(storage.iter().all(|v| *v == 0));
    }
    let mut storage = [0; 4];
    let mut stream = Stream::new(
        StreamConfig {
            max_leaves: 1,
            ..config(Identity::ParallelHashXof128)
        },
        1,
        Mode::Portable,
        &executor,
        &mut storage,
        b"",
    )?;
    let mut no = || false;
    let mut control = Control::new(32, &mut no);
    assert!(stream.update(b"ab", &mut control).is_err());
    cleared(&stream);
    drop(stream);
    let mut stream = Stream::new(
        config(Identity::ParallelHashXof128),
        1,
        Mode::Portable,
        &executor,
        &mut storage,
        b"",
    )?;
    stream.update(b"a", &mut control)?;
    let reader = stream.finalize_xof(&mut control)?;
    core::mem::forget(reader);
    assert!(stream.update(b"b", &mut control).is_err());
    cleared(&stream);
    drop(stream);
    let mut stream = Stream::new(
        config(Identity::ParallelHash128),
        1,
        Mode::Portable,
        &executor,
        &mut storage,
        b"",
    )?;
    let mut yes = || true;
    assert!(
        stream
            .update(b"a", &mut Control::new(32, &mut yes))
            .is_err()
    );
    cleared(&stream);
    Ok(())
}

#[test]
fn empty_stream_completes() -> Result<(), Error> {
    let mut storage = [0; 32];
    let executor = Executor::portable();
    let stream = Stream::new(
        StreamConfig {
            identity: crate::execution::Identity::ParallelHash128,
            max_leaves: 1,
            workers: crate::execution::WorkerPolicy::Mixed,
        },
        8,
        Mode::Portable,
        &executor,
        &mut storage,
        b"",
    )?;
    let mut output = [0; 32];
    let mut no = || false;
    let value = stream.finalize_secret(&mut output, &mut Control::new(0, &mut no))?;
    let mut expected = [0; 32];
    crate::parallel_hash128(b"", &mut [0; 8], b"", &mut expected).map_err(RootError::from)?;
    assert_eq!(value.expose(), expected);
    drop(value);
    assert_eq!(output, [0; 32]);
    assert_eq!(storage, [0; 32]);
    Ok(())
}
