//! Explicit source mutations at integration boundaries, NOT C1/DC1 evidence.
extern crate std;
use super::*;
use core::cell::Cell;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Stage {
    BeforeCopy,
    AfterCopy,
    BetweenReadbacks,
    BeforeSecretWrite,
    BeforeComplete,
}
#[derive(Clone, Copy)]
enum Site {
    Output,
    Primary,
    Secondary,
    State,
}
#[derive(Clone, Copy)]
enum Action {
    Flip(Site, usize, u8),
    Error,
    Unwind,
}
std::thread_local! {
    static PLAN: Cell<Option<(Stage,Action)>> = const { Cell::new(None) };
    static HITS: Cell<usize> = const { Cell::new(0) };
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        PLAN.set(None);
    }
}
fn plan(stage: Stage, action: Action) -> Reset {
    assert!(PLAN.get().is_none());
    PLAN.set(Some((stage, action)));
    HITS.set(0);
    Reset
}

pub(super) fn checkpoint(
    stage: Stage,
    output: &mut [u8; 16],
    primary: &mut [u8; 16],
    secondary: &mut [u8; 16],
    state: &mut [u8; 16],
) -> Result<(), Error> {
    if let Some((selected, action)) = PLAN.get()
        && stage == selected
    {
        HITS.set(HITS.get().wrapping_add(1));
        match action {
            Action::Flip(site, position, mask) => {
                let bytes = match site {
                    Site::Output => output,
                    Site::Primary => primary,
                    Site::Secondary => secondary,
                    Site::State => state,
                };
                *bytes.get_mut(position).ok_or(Error::SecretMemory)? ^= mask;
            }
            Action::Error => return Err(Error::SecretMemory),
            Action::Unwind => resume_unwind(Box::new(())),
        }
    }
    Ok(())
}

pub(super) fn before_complete(state: &mut [u8; 16]) -> Result<(), Error> {
    if let Some((Stage::BeforeComplete, action)) = PLAN.get() {
        HITS.set(HITS.get().wrapping_add(1));
        match action {
            Action::Flip(Site::State, position, mask) => {
                *state.get_mut(position).ok_or(Error::SecretMemory)? ^= mask
            }
            Action::Flip(_, _, _) | Action::Error => return Err(Error::SecretMemory),
            Action::Unwind => resume_unwind(Box::new(())),
        }
    }
    Ok(())
}

fn run(
    owner: &mut Lifecycle,
    output: &mut [u8; 16],
    secret: bool,
    calls: &mut usize,
) -> Result<(), Error> {
    let compute = |p: &mut [u8; 16], s: &mut [u8; 16], completion: &mut Completion| {
        *calls = calls.wrapping_add(1);
        p.fill(0x42);
        s.fill(0x42);
        completion.mark_complete();
        Ok(())
    };
    if secret {
        owner.secret(output, compute).map(|block| {
            assert_eq!(block.expose(), &[0x42; 16]);
            block.clear();
        })
    } else {
        owner.public(output, PublicCiphertext::acknowledge(), compute)
    }
}

fn assert_retired(owner: &mut Lifecycle, output: &mut [u8; 16], secret: bool, calls: &mut usize) {
    assert_eq!(owner.word, TERMINAL);
    assert_eq!(*output, if secret { [0; 16] } else { [0x91; 16] });
    assert_eq!(*calls, 1);
    assert!(run(owner, output, false, calls).is_err());
    assert!(run(owner, output, true, calls).is_err());
    assert_eq!(*calls, 1);
    assert_eq!(*output, [0; 16]);
}

#[test]
fn guarded_transactions_reject_every_modeled_byte_mutation_and_never_reenter() -> Result<(), Error>
{
    let mut cases = 0usize;
    for secret in [false, true] {
        for stage in [
            Stage::BeforeCopy,
            Stage::AfterCopy,
            Stage::BetweenReadbacks,
            Stage::BeforeSecretWrite,
            Stage::BeforeComplete,
        ] {
            if stage == Stage::BeforeSecretWrite && !secret {
                continue;
            }
            for site in [Site::Output, Site::Primary, Site::Secondary, Site::State] {
                if stage == Stage::BeforeCopy && matches!(site, Site::Output) {
                    continue;
                }
                if stage == Stage::BeforeComplete && !matches!(site, Site::State) {
                    continue;
                }
                for position in 0..16 {
                    for mask in 1u8..=255 {
                        let mut owner = Lifecycle::new();
                        let mut output = [0x91; 16];
                        let mut calls = 0;
                        let reset = plan(stage, Action::Flip(site, position, mask));
                        assert!(run(&mut owner, &mut output, secret, &mut calls).is_err());
                        assert_eq!(HITS.get(), 1);
                        drop(reset);
                        assert_retired(&mut owner, &mut output, secret, &mut calls);
                        cases = cases.wrapping_add(1);
                    }
                }
            }
        }
    }
    // Twelve shared stage/site pairs for each path, plus four secret-only
    // pre-write pairs: (12*2 + 4) * 16 positions * 255 nonzero masks.
    assert_eq!(cases, 114_240);
    Ok(())
}

#[test]
fn errors_and_unwinds_at_every_boundary_restore_or_clear_and_retire() {
    let mut cases = 0usize;
    for secret in [false, true] {
        for stage in [
            Stage::BeforeCopy,
            Stage::AfterCopy,
            Stage::BetweenReadbacks,
            Stage::BeforeSecretWrite,
            Stage::BeforeComplete,
        ] {
            if stage == Stage::BeforeSecretWrite && !secret {
                continue;
            }
            for action in [Action::Error, Action::Unwind] {
                let mut owner = Lifecycle::new();
                let mut output = [0x91; 16];
                let mut calls = 0;
                let reset = plan(stage, action);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    run(&mut owner, &mut output, secret, &mut calls)
                }));
                assert_eq!(HITS.get(), 1);
                drop(reset);
                if matches!(action, Action::Unwind) {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
                }
                assert_retired(&mut owner, &mut output, secret, &mut calls);
                cases = cases.wrapping_add(1);
            }
        }
    }
    assert_eq!(cases, 18);
}

#[test]
fn overwritten_old_or_staging_bytes_are_ineffective_not_detected() -> Result<(), Error> {
    for secret in [false, true] {
        for position in 0..16 {
            let mut owner = Lifecycle::new();
            let mut output = [0x91; 16];
            let mut calls = 0;
            let reset = plan(Stage::BeforeCopy, Action::Flip(Site::Output, position, 1));
            run(&mut owner, &mut output, secret, &mut calls)?;
            assert_eq!(HITS.get(), 1);
            drop(reset);
            assert_eq!(owner.word, HEALTHY);
            assert_eq!(output, if secret { [0; 16] } else { [0x42; 16] });
        }
    }
    Ok(())
}
