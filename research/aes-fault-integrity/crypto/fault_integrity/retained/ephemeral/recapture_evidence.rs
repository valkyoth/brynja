//! Source-only mutation after both operation-local key copies. This changes
//! test codegen and is not an emitted-site or fault-qualification experiment.
extern crate std;
use super::super::super::capture::evidence_tests::Mutation;
use super::*;
use core::cell::Cell;

#[derive(Clone, Copy)]
enum Replica {
    Primary,
    Complemented,
}

std::thread_local! {
    static PLAN: Cell<Option<(Replica, usize, Mutation)>> = const { Cell::new(None) };
    static HITS: Cell<usize> = const { Cell::new(0) };
}

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        PLAN.set(None);
    }
}

fn inject(replica: Replica, position: usize, mutation: Mutation) -> Reset {
    assert!(PLAN.get().is_none());
    PLAN.set(Some((replica, position, mutation)));
    HITS.set(0);
    Reset
}

pub(super) fn checkpoint(primary: &mut [u8], complemented: &mut [u8]) {
    if let Some((replica, position, mutation)) = PLAN.get() {
        let target = match replica {
            Replica::Primary => primary,
            Replica::Complemented => complemented,
        };
        if let Some(byte) = target.get_mut(position) {
            *byte = mutation.apply(*byte);
            HITS.set(HITS.get().wrapping_add(1));
        }
    }
}

#[test]
fn local_recapture_mutations_reject_or_preserve_all_owner_paths() -> Result<(), Error> {
    let plain = super::super::tests::answer("00112233445566778899aabbccddeeff")?;
    let mut cases = 0usize;
    let mut rejected = 0usize;
    let mut unchanged = 0usize;
    for (width, text) in [
        (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
        (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (32, "8ea2b7ca516745bfeafc49904b496089"),
    ] {
        let cipher = super::super::tests::answer(text)?;
        let mut key = [0u8; 32];
        for (byte, value) in key.iter_mut().zip(0u8..32) {
            *byte = value;
        }
        for replica in [Replica::Primary, Replica::Complemented] {
            for position in 0..width {
                let key_byte = *key.get(position).ok_or(Error::SecretMemory)?;
                let original = match replica {
                    Replica::Primary => key_byte,
                    Replica::Complemented => !key_byte,
                };
                for mutation in [
                    Mutation::Xor(1),
                    Mutation::Replace(original),
                    Mutation::And(0xfe),
                    Mutation::Or(1),
                ] {
                    for path in 0..3 {
                        let mut primary = [0x91; 34];
                        let mut secondary = [0x92; 34];
                        let end = width.wrapping_add(1);
                        let mut owner = Ephemeral::new(
                            key.get(..width).ok_or(Error::SecretMemory)?,
                            primary.get_mut(1..end).ok_or(Error::SecretMemory)?,
                            secondary.get_mut(1..end).ok_or(Error::SecretMemory)?,
                        )?;
                        let reset = inject(replica, position, mutation);
                        let mut output = [0x93; 16];
                        let input = if path == 2 { &cipher } else { &plain };
                        let expected = if path == 2 { &plain } else { &cipher };
                        let result = if path == 0 {
                            owner.encrypt_public(
                                input,
                                &mut output,
                                PublicCiphertext::acknowledge(),
                            )
                        } else {
                            owner.secret(input, &mut output, path == 2).map(|block| {
                                assert_eq!(block.expose(), expected);
                            })
                        };
                        assert_eq!(HITS.get(), 1);
                        drop(reset);
                        cases = cases.wrapping_add(1);
                        if mutation.apply(original) == original {
                            result?;
                            assert_eq!(output, if path == 0 { *expected } else { [0; 16] });
                            owner.encrypt_public(
                                &plain,
                                &mut output,
                                PublicCiphertext::acknowledge(),
                            )?;
                            assert_eq!(output, cipher);
                            unchanged = unchanged.wrapping_add(1);
                        } else {
                            assert!(result.is_err());
                            assert_eq!(output, if path == 0 { [0x93; 16] } else { [0; 16] });
                            assert!(
                                owner
                                    .encrypt_public(
                                        &plain,
                                        &mut output,
                                        PublicCiphertext::acknowledge(),
                                    )
                                    .is_err()
                            );
                            rejected = rejected.wrapping_add(1);
                        }
                        assert_eq!(
                            owner.keys.primary,
                            key.get(..width).ok_or(Error::SecretMemory)?
                        );
                        assert!(
                            owner
                                .keys
                                .complemented
                                .iter()
                                .zip(key)
                                .all(|(a, b)| *a == !b)
                        );
                        drop(owner);
                        assert_eq!(primary.first(), Some(&0x91));
                        assert_eq!(secondary.first(), Some(&0x92));
                        assert!(
                            primary
                                .get(1..end)
                                .ok_or(Error::SecretMemory)?
                                .iter()
                                .all(|b| *b == 0)
                        );
                        assert!(
                            secondary
                                .get(1..end)
                                .ok_or(Error::SecretMemory)?
                                .iter()
                                .all(|b| *b == 0)
                        );
                        assert!(
                            primary
                                .get(end..)
                                .ok_or(Error::SecretMemory)?
                                .iter()
                                .all(|b| *b == 0x91)
                        );
                        assert!(
                            secondary
                                .get(end..)
                                .ok_or(Error::SecretMemory)?
                                .iter()
                                .all(|b| *b == 0x92)
                        );
                    }
                }
            }
        }
    }
    assert_eq!((cases, rejected, unchanged), (1_728, 864, 864));
    Ok(())
}
