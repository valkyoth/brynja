//! Test-only interruption points, after real primitive work and inside the pair guard.
extern crate std;

use crate::ghash;
use core::cell::RefCell;
use std::collections::VecDeque;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Step {
    Entry,
    Expanded,
    AesBlock,
    #[cfg(any(
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "windows")
        ),
        all(
            target_arch = "aarch64",
            target_endian = "little",
            any(target_os = "linux", target_os = "macos")
        )
    ))]
    HashStart,
    #[cfg(any(
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "windows")
        ),
        all(
            target_arch = "aarch64",
            target_endian = "little",
            any(target_os = "linux", target_os = "macos")
        )
    ))]
    HashUpdate,
    Complete,
}

struct Interrupted;
std::thread_local! {
    static TRAP: RefCell<Option<(VecDeque<Step>, bool)>> = const { RefCell::new(None) };
}

impl Step {
    pub(crate) fn hit(self) -> Result<(), ghash::Error> {
        TRAP.with_borrow_mut(|trap| {
            let Some((prefix, unwind)) = trap else {
                return Ok(());
            };
            assert_eq!(
                prefix.pop_front(),
                Some(self),
                "unexpected native execution stage"
            );
            if !prefix.is_empty() {
                return Ok(());
            }
            if *unwind {
                std::panic::resume_unwind(std::boxed::Box::new(Interrupted));
            }
            Err(ghash::Error::Quarantined)
        })
    }
}

#[cfg(all(
    any(
        all(
            all(
                target_arch = "x86_64",
                any(target_os = "linux", target_os = "windows")
            ),
            target_feature = "aes",
            target_feature = "sse2"
        ),
        all(
            all(
                target_arch = "aarch64",
                target_endian = "little",
                any(target_os = "linux", target_os = "macos")
            ),
            target_feature = "aes",
            target_feature = "neon"
        )
    ),
    feature = "aes-gcm-execution",
    feature = "gmac-execution"
))]
pub(crate) mod tests {
    use super::{Interrupted, Step, TRAP, std};
    use crate::{
        aes_gcm::{self as gcm, GcmError, execution::AesPair},
        gmac::{self, GmacError},
    };
    use Step::{
        AesBlock as A, Complete as C, Entry as E, Expanded as X, HashStart as H, HashUpdate as U,
    };
    use std::{
        fmt::Debug,
        panic::{AssertUnwindSafe, catch_unwind},
        string::String,
    };

    fn detail(e: impl Debug) -> String {
        std::format!("{e:?}")
    }

    // Each scenario creates a new owner and pair. Require the entire named
    // prefix, the specific interruption outcome, and no later checkpoints.
    pub(crate) fn interrupt<T, Err: Debug + PartialEq>(
        prefix: &[Step],
        unwind: bool,
        error: Err,
        f: impl FnOnce() -> Result<T, Err>,
    ) {
        TRAP.with_borrow_mut(|trap| {
            assert!(
                trap.replace((prefix.iter().copied().collect(), unwind))
                    .is_none()
            )
        });
        let outcome = catch_unwind(AssertUnwindSafe(f));
        let trap = TRAP.with_borrow_mut(Option::take);
        assert!(
            trap.is_some_and(|(left, _)| left.is_empty()),
            "stage not reached"
        );
        match outcome {
            Ok(result) => {
                assert!(!unwind);
                assert_eq!(result.err(), Some(error));
            }
            Err(panic) => {
                assert!(unwind && panic.is::<Interrupted>(), "unexpected unwind");
            }
        }
    }

    fn sweep(
        path: &[Step],
        mut case: impl FnMut(&[Step], bool) -> Result<(), String>,
    ) -> Result<(), String> {
        for n in 1..=path.len() {
            let prefix = path.get(..n).ok_or("invalid test prefix")?;
            case(prefix, false)?;
            case(prefix, true)?;
        }
        Ok(())
    }

    // Nonempty updates, not individual products. J0: IV, pad, two lengths.
    // Message: AAD, pad, text, pad, two lengths. Two CTR blocks, one partial.
    const SEAL: &[Step] = &[E, A, H, U, U, U, U, A, A, A, H, U, U, U, U, U, U, C];
    const OPEN: &[Step] = &[E, A, H, U, U, U, U, A, H, U, U, U, U, U, U, A, A, C];
    const REJECT: &[Step] = &[E, A, H, U, U, U, U, A, H, U, U, U, U, U, U, C];
    // 96-bit IV shortcut and 17 bytes of GMAC AAD: no IV hash or CTR.
    const MAC: &[Step] = &[E, A, A, H, U, U, U, U, C];
    const AAD: &[u8] = &[0x27; 17];
    const PLAIN: [u8; 17] = [0x43; 17];

    macro_rules! width {
        ($name:ident, $g:ident, $m:ident, $k:literal, $s:literal) => {
            mod $name {
                use super::*;
                #[test]
                fn import() -> Result<(), String> {
                    sweep(&[E, X, C], |prefix, unwind| {
                        let pair = AesPair::require().map_err(detail)?;
                        let (mut storage, mut sibling) = ([0xa5; $s], [0; $s]);
                        let mut mac = gmac::execution::$m::<16>::from_reserved_range(
                            &pair,
                            &[0x71; $k],
                            &mut sibling,
                            *b"auth",
                            1,
                            1,
                        )
                        .map_err(detail)?;
                        interrupt(prefix, unwind, GcmError::Operation, || {
                            gcm::execution::$g::<16>::for_open(&pair, &[0x29; $k], &mut storage)
                        });
                        assert_eq!(storage, [0; $s]);
                        assert_eq!(mac.authenticate_next(AAD).err(), Some(GmacError::Operation));
                        Ok(())
                    })
                }

                #[test]
                fn messages() -> Result<(), String> {
                    let mut reference = [0; $s];
                    let key = [0x51; $k];
                    let mut oracle = gcm::$g::<13, 8>::from_reserved_invocations(
                        &key,
                        &mut reference,
                        b"iv-a",
                        1,
                        1,
                    )
                    .map_err(detail)?;
                    let mut ciphertext = PLAIN;
                    let (iv, tag) = oracle
                        .seal_next_in_place(AAD, &mut ciphertext, &mut [0; 17])
                        .map_err(detail)?;
                    let mut bad = tag;
                    bad[0] ^= 1;
                    for (seal, candidate, path) in [
                        (true, &tag, SEAL),
                        (false, &tag, OPEN),
                        (false, &bad, REJECT),
                    ] {
                        for in_place in [true, false] {
                            sweep(path, |prefix, unwind| {
                                let pair = AesPair::require().map_err(detail)?;
                                let mut storage = [0; $s];
                                let mut sender =
                                    gcm::execution::$g::<13, 8>::from_reserved_invocations(
                                        &pair,
                                        &key,
                                        &mut storage,
                                        b"iv-a",
                                        1,
                                        1,
                                    )
                                    .map_err(detail)?;
                                let initial = if !in_place {
                                    [0x5a; 17]
                                } else if seal {
                                    PLAIN
                                } else {
                                    ciphertext
                                };
                                let (mut data, mut scratch) = (initial, [0xff; 17]);
                                interrupt(prefix, unwind, GcmError::Operation, || {
                                    match (seal, in_place) {
                                        (true, true) => sender
                                            .seal_next_in_place(AAD, &mut data, &mut scratch)
                                            .map(drop),
                                        (true, false) => sender
                                            .seal_next(AAD, &PLAIN, &mut data, &mut scratch)
                                            .map(drop),
                                        (false, true) => sender.open_in_place(
                                            &iv,
                                            AAD,
                                            candidate,
                                            &mut data,
                                            &mut scratch,
                                        ),
                                        (false, false) => sender.open(
                                            &iv,
                                            AAD,
                                            candidate,
                                            &ciphertext,
                                            &mut data,
                                            &mut scratch,
                                        ),
                                    }
                                });
                                assert_eq!((data, scratch), (initial, [0; 17]));
                                assert_eq!(
                                    sender.open_in_place(&iv, AAD, &tag, &mut data, &mut scratch),
                                    Err(GcmError::Operation)
                                );
                                if !seal {
                                    // Opening did not spend the allocation. The first
                                    // send now burns it and sees the terminal pair.
                                    assert_eq!(
                                        sender.seal_next_in_place(AAD, &mut data, &mut scratch),
                                        Err(GcmError::Operation)
                                    );
                                }
                                assert_eq!(
                                    sender.seal_next_in_place(AAD, &mut data, &mut scratch),
                                    Err(GcmError::Exhausted)
                                );
                                drop(sender);
                                assert_eq!(storage, [0; $s]);
                                Ok(())
                            })?;
                        }
                    }
                    Ok(())
                }

                #[test]
                fn authentication_only() -> Result<(), String> {
                    let key = [0x71; $k];
                    let mut reference = [0; $s];
                    let mut oracle =
                        gmac::$m::<16>::from_reserved_range(&key, &mut reference, *b"auth", 1, 1)
                            .map_err(detail)?;
                    let (iv, tag) = oracle.authenticate_next(AAD).map_err(detail)?;
                    // Successful and rejected verification have the same stage
                    // sequence. Neither may mask a concurrent operational error.
                    for (generate, aad) in [(true, AAD), (false, AAD), (false, &[0x28; 17][..])] {
                        sweep(MAC, |prefix, unwind| {
                            let pair = AesPair::require().map_err(detail)?;
                            let mut storage = [0; $s];
                            let mut mac = gmac::execution::$m::<16>::from_reserved_range(
                                &pair,
                                &key,
                                &mut storage,
                                *b"auth",
                                1,
                                1,
                            )
                            .map_err(detail)?;
                            interrupt(prefix, unwind, GmacError::Operation, || {
                                if generate {
                                    mac.authenticate_next(aad).map(drop)
                                } else {
                                    mac.verify(&iv, aad, &tag)
                                }
                            });
                            assert_eq!(mac.verify(&iv, AAD, &tag), Err(GmacError::Operation));
                            if !generate {
                                assert_eq!(
                                    mac.authenticate_next(AAD).err(),
                                    Some(GmacError::Operation)
                                );
                            }
                            assert_eq!(
                                mac.authenticate_next(AAD).err(),
                                Some(GmacError::Exhausted)
                            );
                            drop(mac);
                            assert_eq!(storage, [0; $s]);
                            Ok(())
                        })?;
                    }
                    Ok(())
                }
            }
        };
    }
    width!(aes128, Aes128Gcm, Aes128Gmac, 16, 176);
    width!(aes192, Aes192Gcm, Aes192Gmac, 24, 208);
    width!(aes256, Aes256Gcm, Aes256Gmac, 32, 240);
}
