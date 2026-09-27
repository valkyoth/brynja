use super::*;
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};

// Native tests always execute the full matrix, regardless of ambient values.
fn miri_case(total: usize) -> Option<usize> {
    let selected = if cfg!(miri) {
        std::env::var("BRYNJA_MIRI_CASE").ok().map(|value| {
            let parsed = value.parse::<usize>();
            assert!(parsed.is_ok());
            parsed.unwrap_or(usize::MAX)
        })
    } else {
        None
    };
    assert!(selected.is_none_or(|case| case < total));
    selected
}

fn miri_complete(selected: Option<usize>, executed: usize, total: usize, _name: &str) {
    assert_eq!(executed, if selected.is_some() { 1 } else { total });
    #[cfg(miri)]
    if let Some(case) = selected {
        std::println!("\nMIRI_CASE_PASS: {_name}:{case}");
    }
}

fn cleared(owner: &Sha1Owner) {
    assert_eq!(owner.chaining_state, [0; 20]);
    assert_eq!(owner.block, [0; 64]);
    assert_eq!(owner.schedule, [0; 320]);
    assert_eq!(owner.message_length, [0; 8]);
    assert_eq!(owner.buffered, [0; 1]);
    assert_eq!(owner.output_staging, [0; 20]);
}
fn poison(owner: &mut Sha1Owner) {
    owner.chaining_state.fill(0xa5);
    owner.block.fill(0xa5);
    owner.schedule.fill(0xa5);
    owner.message_length.fill(0xa5);
    owner.buffered.fill(0xa5);
    owner.output_staging.fill(0xa5);
}

#[test]
fn scoped_sha1_streaming_bits_reuse_and_output_lifetime() -> Result<(), Sha1Error> {
    let selected = miri_case(288);
    let mut visited = 0;
    let mut executed = 0;
    let mut workspace = Sha1Workspace::new();
    let message = [0xa5; 129];
    for size in [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129] {
        let input = message.get(..size).ok_or(Sha1Error::OutputLength)?;
        for width in [1, 7, 64] {
            for bits in 0..8 {
                let index = visited;
                visited += 1;
                if selected.is_some_and(|case| case != index) {
                    continue;
                }
                executed += 1;
                let tail = [0x80];
                let tail = if bits == 0 {
                    empty()?
                } else {
                    BitString::new(&tail, bits).map_err(|_| Sha1Error::MessageTooLong)?
                };
                let mut reference = crate::HardenedSha1::new();
                reference.update(input)?;
                let mut expected = [0; 20];
                reference.finalize_bits_public(
                    tail,
                    &mut expected,
                    PublicDeclassification::acknowledge(),
                )?;
                let mut output = [0xa5; 20];
                let secret = workspace.with(|mut state| {
                    for chunk in input.chunks(width) {
                        state.update(chunk)?;
                        state.update(&[])?;
                    }
                    state.finalize_bits_secret(tail, &mut output)
                })?;
                assert_eq!(secret.expose(), expected);
                cleared(&workspace.owner);
                drop(secret);
                assert_eq!(output, [0; 20]);
                workspace.with(|mut state| {
                    state.update(input)?;
                    state.finalize_bits_public(
                        tail,
                        &mut output,
                        PublicDeclassification::acknowledge(),
                    )
                })?;
                assert_eq!(output, expected);
                cleared(&workspace.owner);
            }
        }
    }
    assert_eq!(visited, 288);
    miri_complete(selected, executed, 288, "sha1-scoped");
    Ok(())
}

#[test]
fn scoped_sha1_guards_cover_forgotten_handle_and_unwind() {
    let mut workspace = Sha1Workspace::new();
    for unwind in [false, true] {
        let result = catch_unwind(AssertUnwindSafe(|| {
            workspace.with(|state| {
                poison(state.owner);
                core::mem::forget(state);
                if unwind {
                    std::panic::resume_unwind(std::boxed::Box::new(()));
                }
            })
        }));
        assert_eq!(result.is_err(), unwind);
        cleared(&workspace.owner);
    }
    // Handle destruction is separately required, even before scope exit.
    let mut owner = Sha1Owner::new();
    poison(&mut owner);
    Sha1 {
        owner: &mut owner,
        active: true,
        thread_bound: PhantomData,
    }
    .cancel();
    cleared(&owner);
}

#[test]
fn scoped_sha1_initialization_overwrites_all_previous_storage() {
    let mut workspace = Sha1Workspace::new();
    poison(&mut workspace.owner);
    workspace.with(|state| {
        let initial = Sha1Owner::new();
        assert_eq!(state.owner.chaining_state, initial.chaining_state);
        assert_eq!(state.owner.block, [0; 64]);
        assert_eq!(state.owner.schedule, [0; 320]);
        assert_eq!(state.owner.message_length, [0; 8]);
        assert_eq!(state.owner.buffered, [0; 1]);
        assert_eq!(state.owner.output_staging, [0; 20]);
    });
    cleared(&workspace.owner);
}

#[test]
fn scoped_sha1_update_failure_and_unwind_are_terminal() {
    let mut workspace = Sha1Workspace::new();
    for unwind in [false, true] {
        workspace.with(|mut state| {
            if unwind {
                state.owner.buffered = [64];
            } else {
                state.owner.message_length = (u64::MAX - 7).to_be_bytes();
            }
            let result = catch_unwind(AssertUnwindSafe(|| state.update(&[1])));
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(result.is_ok_and(|r| r == Err(Sha1Error::MessageTooLong)));
            }
            cleared(state.owner);
            assert_eq!(state.update(&[]), Err(Sha1Error::StateConsumed));
            let mut output = [0xa5; 20];
            assert!(matches!(
                state.finalize_secret(&mut output),
                Err(Sha1Error::StateConsumed)
            ));
            assert_eq!(output, [0; 20]);
        });
        cleared(&workspace.owner);
    }
}

#[test]
fn scoped_sha1_error_and_unwind_destinations() -> Result<(), Sha1Error> {
    let mut workspace = Sha1Workspace::new();
    for size in 0..=40 {
        if size == 20 {
            continue;
        }
        let mut bytes = [0xa5; 40];
        let output = bytes.get_mut(..size).ok_or(Sha1Error::OutputLength)?;
        assert_eq!(
            workspace
                .with(|state| state.finalize_public(output, PublicDeclassification::acknowledge())),
            Err(Sha1Error::OutputLength)
        );
        assert!(output.iter().all(|b| *b == 0xa5));
        assert!(matches!(
            workspace.with(|state| state.finalize_secret(output)),
            Err(Sha1Error::OutputLength)
        ));
        assert!(output.iter().all(|b| *b == 0));
        assert!(
            bytes
                .get(size..)
                .ok_or(Sha1Error::OutputLength)?
                .iter()
                .all(|b| *b == 0xa5)
        );
        cleared(&workspace.owner);
    }
    for secret in [false, true] {
        for unwind in [false, true] {
            let mut output = [0xa5; 20];
            let result = catch_unwind(AssertUnwindSafe(|| {
                workspace.with(|state| {
                    if unwind {
                        state.owner.buffered = [64];
                    } else {
                        state.owner.message_length = u64::MAX.to_be_bytes();
                    }
                    let tail = BitString::new(&[0x80], 1).map_err(|_| Sha1Error::MessageTooLong)?;
                    if secret {
                        state.finalize_bits_secret(tail, &mut output).map(drop)
                    } else {
                        state.finalize_bits_public(
                            tail,
                            &mut output,
                            PublicDeclassification::acknowledge(),
                        )
                    }
                })
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(result.is_ok_and(|r| r == Err(Sha1Error::MessageTooLong)));
            }
            assert_eq!(output, if secret { [0; 20] } else { [0xa5; 20] });
            cleared(&workspace.owner);
        }
    }
    Ok(())
}
