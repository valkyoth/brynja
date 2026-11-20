//! Explicit functional campaign, not fault-model or release admission.
use super::*;
use crate::aes::fault_integrity::cipher_avs_tests::{MONTE_CARLO_CORPORA, next_key};

fn iterate(
    owner: &mut Owner<'_, '_>,
    input: [u8; 16],
    inverse: bool,
) -> Result<([u8; 16], [u8; 16]), Error> {
    let mut current = input;
    let mut previous = input;
    let mut guarded = [0x93; 18];
    for index in 0usize..1000 {
        previous = current;
        let destination: &mut [u8; 16] = guarded
            .get_mut(1..17)
            .ok_or(Error::SecretMemory)?
            .try_into()
            .map_err(|_| Error::SecretMemory)?;
        destination.fill(0x93);
        let block = owner.secret(&current, destination, inverse)?;
        current.copy_from_slice(block.expose());
        if index.is_multiple_of(2) {
            block.clear();
        } else {
            drop(block);
        }
        assert!(destination.iter().all(|byte| *byte == 0));
        assert_eq!(guarded[0], 0x93);
        assert_eq!(guarded[17], 0x93);
    }
    Ok((previous, current))
}

#[test]
#[ignore = "explicit 1,200,000-call composite AESAVS campaign; run --release --ignored"]
fn frozen_monte_carlo_chains_through_both_owners() -> Result<(), Error> {
    let mut imports = 0usize;
    let mut calls = 0usize;
    for (text, width) in MONTE_CARLO_CORPORA {
        let end = width.checked_add(1).ok_or(Error::SecretMemory)?;
        let cases = records(text, width, true)?;
        let (sections, remainder) = cases.as_chunks::<100>();
        assert!(remainder.is_empty() && sections.len() == 2);
        for operation_local in [false, true] {
            for (inverse, section) in [false, true].into_iter().zip(sections) {
                let mut key = section[0].key.clone();
                let mut input: [u8; 16] = section[0]
                    .input
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::SecretMemory)?;
                for (index, case) in section.iter().enumerate() {
                    assert!(
                        case.inverse == inverse && case.key == key && case.input == input,
                        "composite MCT chain mismatch: width {width}, inverse {inverse}, local {operation_local}, record {index}"
                    );
                    let mut primary = [0x91; 34];
                    let mut secondary = [0x92; 34];
                    let (previous, last) = {
                        let first = primary.get_mut(1..end).ok_or(Error::SecretMemory)?;
                        let second = secondary.get_mut(1..end).ok_or(Error::SecretMemory)?;
                        let mut cached;
                        let mut local;
                        let mut owner = if operation_local {
                            local = ephemeral::Ephemeral::new(&key, first, second)?;
                            Owner::Local(&mut local)
                        } else {
                            cached = Cached::new(&key, first, second)?;
                            Owner::Cached(&mut cached)
                        };
                        iterate(&mut owner, input, inverse)?
                    };
                    assert!(
                        case.expected == last,
                        "composite MCT output mismatch: width {width}, inverse {inverse}, local {operation_local}, record {index}"
                    );
                    for (storage, sentinel) in [(&primary, 0x91), (&secondary, 0x92)] {
                        assert!(
                            storage
                                .get(1..end)
                                .ok_or(Error::SecretMemory)?
                                .iter()
                                .all(|byte| *byte == 0)
                        );
                        assert_eq!(storage[0], sentinel);
                        assert!(
                            storage
                                .get(end..)
                                .ok_or(Error::SecretMemory)?
                                .iter()
                                .all(|byte| *byte == sentinel)
                        );
                    }
                    key = next_key(&key, &previous, &last)?;
                    input = last;
                    imports = imports.checked_add(1).ok_or(Error::SecretMemory)?;
                    calls = calls.checked_add(1000).ok_or(Error::SecretMemory)?;
                }
            }
        }
    }
    assert_eq!(imports, 1200);
    assert_eq!(calls, 1_200_000);
    Ok(())
}
