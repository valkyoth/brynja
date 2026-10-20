//! Exercise the actual sealed hash adapters in a private copied-source crate.
//! This observes live digest storage, not dead stack memory or register erasure.
extern crate std;

use crate::{Algorithm, Error};
use std::{cell::Cell, panic::AssertUnwindSafe};

#[derive(Clone, Copy, Debug)]
enum Exit {
    Return,
    Error,
    Unwind,
}

fn adapter<A: Algorithm>(bits: A::FinalInput<'_>) -> usize {
    adapter_with::<A>(bits, A::start)
}

pub(crate) fn adapter_with<A: Algorithm>(
    bits: A::FinalInput<'_>,
    mut start: impl FnMut() -> Result<A::State, Error>,
) -> usize {
    let mut cases = 0;
    // All three handoffs: normalization/byte final, bit final, outer digest.
    for operation in 0..3 {
        let mut expected = [0; 64];
        for exit in [Exit::Return, Exit::Error, Exit::Unwind] {
            let mut output = [0xa5; 64];
            let calls = Cell::new(0);
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let mut state = start()?;
                A::update(&mut state, b"adapter handoff prefix")?;
                let consume = |digest: &[u8]| {
                    calls.set(calls.get() + 1);
                    assert_eq!(digest.len(), A::TAG_BYTES);
                    assert!(digest.iter().any(|byte| *byte != 0), "non-vacuous digest");
                    if matches!(exit, Exit::Return) {
                        expected[..A::TAG_BYTES].copy_from_slice(digest);
                    } else {
                        assert_eq!(digest, &expected[..A::TAG_BYTES]);
                    }
                    match exit {
                        Exit::Return => Ok(()),
                        Exit::Error => Err(Error::MessageTooLong),
                        Exit::Unwind => panic!("synthetic adapter consumer unwind"),
                    }
                };
                let destination = &mut output[..A::TAG_BYTES];
                match operation {
                    0 => A::finish(state, destination, consume),
                    1 => A::finish_bits(state, bits, destination, consume),
                    // Zero is canonical even for non-byte general SHA-512/t.
                    _ => A::finish_outer(state, &[0; 64][..A::TAG_BYTES], destination, consume),
                }
            }));
            match exit {
                Exit::Return => assert!(matches!(result, Ok(Ok(())))),
                Exit::Error => assert!(matches!(result, Ok(Err(Error::MessageTooLong)))),
                Exit::Unwind => assert!(result.is_err()),
            }
            assert_eq!(calls.get(), 1, "adapter must commit exactly once");
            assert_eq!(&output[..A::TAG_BYTES], std::vec![0; A::TAG_BYTES]);
            assert!(output[A::TAG_BYTES..].iter().all(|byte| *byte == 0xa5));
            cases += 1;
        }
        // A rejected destination must not call the consumer or retain output.
        let mut output = [0xa5; 64];
        let calls = Cell::new(0);
        let state = start().expect("valid adapter");
        let consume = |_: &[u8]| {
            calls.set(calls.get() + 1);
            Ok(())
        };
        let destination = &mut output[..A::TAG_BYTES - 1];
        let result = match operation {
            0 => A::finish(state, destination, consume),
            1 => A::finish_bits(state, bits, destination, consume),
            _ => A::finish_outer(state, &[0; 64][..A::TAG_BYTES], destination, consume),
        };
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
        assert!(output[..A::TAG_BYTES - 1].iter().all(|byte| *byte == 0));
        assert!(output[A::TAG_BYTES - 1..].iter().all(|byte| *byte == 0xa5));
        cases += 1;
    }
    cases
}

#[test]
fn real_adapter_consumers_release_digest_on_every_exit() {
    let sha2 = crate::Sha2BitString::new(&[0x80], 1).expect("canonical");
    let sha3 = crate::Fips202BitString::new(&[1], 1).expect("canonical");
    let cases = adapter::<crate::Sha224>(sha2)
        + adapter::<crate::Sha256>(sha2)
        + adapter::<crate::Sha384>(sha2)
        + adapter::<crate::Sha512>(sha2)
        + adapter::<crate::Sha512_224>(sha2)
        + adapter::<crate::Sha512_256>(sha2)
        + adapter::<crate::Sha3_224>(sha3)
        + adapter::<crate::Sha3_256>(sha3)
        + adapter::<crate::Sha3_384>(sha3)
        + adapter::<crate::Sha3_512>(sha3)
        + adapter::<crate::Sha512T<129>>(sha2)
        + adapter::<crate::Sha512T<511>>(sha2);
    assert_eq!(cases, 144, "real adapter handoff population changed");
}
