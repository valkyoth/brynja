//! Source-only late fault fixture. It is not native fault evidence.
extern crate std;
use super::*;
use core::cell::Cell;

std::thread_local! {
    static POSITION: Cell<Option<usize>> = const { Cell::new(None) };
    static HITS: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn checkpoint(retained: &mut Retained<'_>) -> Result<(), Error> {
    if let Some(position) = POSITION.get() {
        let byte = retained
            .keys
            .primary
            .get_mut(position)
            .ok_or(Error::SecretMemory)?;
        *byte ^= 1;
        HITS.set(HITS.get().wrapping_add(1));
    }
    Ok(())
}

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        POSITION.set(None);
    }
}

#[test]
fn late_local_key_fault_with_forged_success_cannot_release() -> Result<(), Error> {
    let input = super::super::tests::answer("00112233445566778899aabbccddeeff")?;
    for width in [16usize, 24, 32] {
        let key = [0x42; 32];
        for path in 0..3 {
            let inverse = path == 2;
            let secret = path != 0;
            let mut first = [0x91; 32];
            let mut second = [0x92; 32];
            let mut owner = Ephemeral::new(
                key.get(..width).ok_or(Error::SecretMemory)?,
                first.get_mut(..width).ok_or(Error::SecretMemory)?,
                second.get_mut(..width).ok_or(Error::SecretMemory)?,
            )?;
            POSITION.set(Some(width.wrapping_sub(1)));
            HITS.set(0);
            let reset = Reset;
            let mut output = [0x93; 16];
            let forged =
                |p: &mut [u8; 16],
                 s: &mut [u8; 16],
                 completion: &mut super::super::super::transaction::Completion| {
                    // The inner engine completed, then the late local-key
                    // corruption made the outer check fail. Ignore only that
                    // returned Err to model a single forged success result.
                    assert!(
                        Ephemeral::compute(&owner.keys, &input, p, s, inverse, completion,)
                            .is_err()
                    );
                    Ok(())
                };
            let failed = if secret {
                owner.lifecycle.secret(&mut output, forged).is_err()
            } else {
                owner
                    .lifecycle
                    .public(&mut output, PublicCiphertext::acknowledge(), forged)
                    .is_err()
            };
            assert!(failed);
            assert_eq!(HITS.get(), 1);
            drop(reset);
            assert_eq!(output, if secret { [0; 16] } else { [0x93; 16] });
            assert!(
                owner
                    .encrypt_public(&input, &mut output, PublicCiphertext::acknowledge())
                    .is_err()
            );
            assert!(owner.secret(&input, &mut output, inverse).is_err());
            drop(owner);
            assert!(
                first
                    .get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|b| *b == 0)
            );
            assert!(
                second
                    .get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|b| *b == 0)
            );
        }
    }
    Ok(())
}
