use super::*;
use crate::ParallelHashPublicDeclassification as Public;
use crate::execution::{Identity, WorkerPolicy};
extern crate std;
fn config(identity: Identity) -> StreamConfig {
    StreamConfig {
        identity,
        max_leaves: 32,
        workers: WorkerPolicy::Mixed,
    }
}
#[test]
fn output_failures_and_reader_drop_clear_the_owner() -> Result<(), Error> {
    let executor = Executor::portable();
    let mut no = || false;
    let mut control = Control::new(64, &mut no);
    for kind in 0..5 {
        let mut storage = [0; 4];
        let identity = if kind >= 2 {
            Identity::ParallelHashXof128
        } else {
            Identity::ParallelHash128
        };
        let mut stream = Stream::new(
            config(identity),
            1,
            Mode::Portable,
            &executor,
            &mut storage,
            b"",
        )?;
        stream.update(b"a", &mut control)?;
        let mut out = [0xa5; 32];
        let mut scratch = [0xff; 31];
        match kind {
            0 => {
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
                assert_eq!(scratch, [0; 31]);
            }
            1 => {
                assert!(
                    stream
                        .finalize_secret_bits(
                            crate::execution::bits(&[])?,
                            &mut out,
                            0,
                            &mut control
                        )
                        .is_err()
                );
                assert_eq!(out, [0; 32]);
            }
            2 => {
                let mut reader = stream.finalize_xof(&mut control)?;
                assert!(
                    reader
                        .squeeze_public(&mut out, &mut scratch, Public::acknowledge())
                        .is_err()
                );
                assert_eq!(out, [0xa5; 32]);
                assert_eq!(scratch, [0; 31]);
                assert!(reader.squeeze_secret(&mut out).is_err());
                assert_eq!(out, [0; 32]);
                drop(reader);
                drop(stream);
            }
            3 => {
                let reader = stream.finalize_xof(&mut control)?;
                let value = reader.squeeze_final_secret(&mut out, 5)?;
                assert_eq!(*value.expose().get(31).ok_or(RootError::State)? & 0xe0, 0);
                drop(value);
                assert_eq!(out, [0; 32]);
                drop(stream);
            }
            _ => {
                let reader = stream.finalize_xof(&mut control)?;
                drop(reader);
                assert_eq!(stream.input_bits, [0; 16]);
                assert_eq!(stream.root.merged_leaves(), 0);
                assert!(stream.update(b"x", &mut control).is_err());
                drop(stream);
            }
        }
        assert_eq!(storage, [0; 4]);
    }
    Ok(())
}
#[test]
fn required_tail_and_revocation_do_not_fall_back() -> Result<(), Error> {
    let kernel = if cfg!(target_arch = "aarch64") {
        batch::Kernel::Neon
    } else {
        batch::Kernel::Avx2
    };
    if !kernel.compiled() {
        assert!(std::env::var_os("BRYNJA_REQUIRE_PARALLELHASH_BATCH").is_none());
        return Ok(());
    }
    for kind in 0..4 {
        let owner = batch::Authority::for_compiled_target(kernel)
            .map_err(brynja_hash_sha3::hardened_batch::Error::Backend)?;
        let executor = Executor::with_session(
            owner
                .session()
                .map_err(brynja_hash_sha3::hardened_batch::Error::Backend)?,
            batch::Mode::Require,
            1,
        )?;
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
        assert_eq!(stream.accelerated_leaves(), 4);
        stream.update(b"e", &mut control)?;
        if kind == 1 {
            executor.quarantine();
        }
        if kind == 2 {
            executor.quarantine();
            assert!(stream.update(&[], &mut control).is_err());
        }
        let mut out = [0xa5; 32];
        let mut scratch = [0xff; 32];
        if kind == 3 {
            assert!(stream.finalize_secret(&mut out, &mut control).is_err());
            assert_eq!(out, [0; 32]);
        } else {
            assert!(
                stream
                    .finalize_public(&mut out, &mut scratch, Public::acknowledge(), &mut control)
                    .is_err()
            );
            assert_eq!(out, [0xa5; 32]);
            assert_eq!(scratch, [0; 32]);
        }
        assert_eq!(storage, [0; 4]);
    }
    Ok(())
}
