//! Frozen-answer composition checks, not release or fault qualification.
use super::super::cipher_avs_tests::{CORPORA, records};
use super::*;

mod monte_carlo;

// Test-only dispatch across the two private owner lifetimes.
enum Owner<'owner, 'key> {
    Cached(&'owner mut Cached<'key>),
    Local(&'owner mut ephemeral::Ephemeral<'key>),
}

impl Owner<'_, '_> {
    fn secret<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, Error> {
        match self {
            Self::Cached(owner) => owner.secret(input, output, inverse),
            Self::Local(owner) => owner.secret(input, output, inverse),
        }
    }

    fn public(&mut self, input: &[u8; 16], output: &mut [u8; 16]) -> Result<(), Error> {
        match self {
            Self::Cached(owner) => {
                owner.encrypt_public(input, output, PublicCiphertext::acknowledge())
            }
            Self::Local(owner) => {
                owner.encrypt_public(input, output, PublicCiphertext::acknowledge())
            }
        }
    }
}

#[test]
fn frozen_multiblock_answers_through_both_owners_and_output_routes() -> Result<(), Error> {
    let mut imports = 0usize;
    let mut secret_calls = 0usize;
    let mut public_calls = 0usize;
    for (text, width) in CORPORA {
        let end = width.checked_add(1).ok_or(Error::SecretMemory)?;
        for case in records(text, width, false)? {
            for operation_local in [false, true] {
                let mut primary = [0x91; 34];
                let mut secondary = [0x92; 34];
                let mut destination = [0x93; 18];
                {
                    let first = primary.get_mut(1..end).ok_or(Error::SecretMemory)?;
                    let second = secondary.get_mut(1..end).ok_or(Error::SecretMemory)?;
                    let mut cached;
                    let mut local;
                    let mut owner = if operation_local {
                        local = ephemeral::Ephemeral::new(&case.key, first, second)?;
                        Owner::Local(&mut local)
                    } else {
                        cached = Cached::new(&case.key, first, second)?;
                        Owner::Cached(&mut cached)
                    };
                    imports = imports.checked_add(1).ok_or(Error::SecretMemory)?;
                    let (inputs, input_tail) = case.input.as_chunks::<16>();
                    let (expected, output_tail) = case.expected.as_chunks::<16>();
                    assert!(input_tail.is_empty() && output_tail.is_empty());
                    assert_eq!(inputs.len(), expected.len());
                    for (index, (input, expected)) in inputs.iter().zip(expected).enumerate() {
                        let output: &mut [u8; 16] = destination
                            .get_mut(1..17)
                            .ok_or(Error::SecretMemory)?
                            .try_into()
                            .map_err(|_| Error::SecretMemory)?;
                        output.fill(0x93);
                        let secret = owner.secret(input, output, case.inverse)?;
                        assert!(
                            secret.expose() == expected,
                            "composite MMT secret answer mismatch"
                        );
                        if index.is_multiple_of(2) {
                            secret.clear();
                        } else {
                            drop(secret);
                        }
                        assert!(output.iter().all(|byte| *byte == 0));
                        secret_calls = secret_calls.checked_add(1).ok_or(Error::SecretMemory)?;
                        if !case.inverse {
                            owner.public(input, output)?;
                            assert!(output == expected, "composite MMT public answer mismatch");
                            public_calls =
                                public_calls.checked_add(1).ok_or(Error::SecretMemory)?;
                        }
                        assert_eq!(destination[0], 0x93);
                        assert_eq!(destination[17], 0x93);
                    }
                }
                assert!(
                    primary
                        .get(1..end)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|byte| *byte == 0)
                );
                assert!(
                    secondary
                        .get(1..end)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|byte| *byte == 0)
                );
                assert_eq!(primary[0], 0x91);
                assert_eq!(secondary[0], 0x92);
                assert!(
                    primary
                        .get(end..)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|byte| *byte == 0x91)
                );
                assert!(
                    secondary
                        .get(end..)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|byte| *byte == 0x92)
                );
            }
        }
    }
    assert_eq!(imports, 120);
    assert_eq!(secret_calls, 660);
    assert_eq!(public_calls, 330);
    Ok(())
}
