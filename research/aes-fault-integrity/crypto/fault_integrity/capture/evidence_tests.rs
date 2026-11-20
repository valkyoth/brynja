//! Source-checkpoint tests, not corruption of the assembly or linked artifact.
extern crate std;
use super::*;
use core::cell::Cell;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};
#[derive(Clone, Copy)]
pub(in super::super) enum Action {
    Flip(usize),
    Mutate(usize, Mutation),
    Error,
    Unwind,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in super::super) enum Stage {
    AfterFirst,
    AfterSecond,
}

// Finite source mutations, not CPU register/instruction faults. AND/OR masks
// include single-bit stuck-at-zero/one cases and their ineffective outcomes.
#[derive(Clone, Copy)]
pub(in super::super) enum Mutation {
    Xor(u8),
    Replace(u8),
    And(u8),
    Or(u8),
}
impl Mutation {
    pub(in super::super) fn apply(self, original: u8) -> u8 {
        match self {
            Self::Xor(mask) => original ^ mask,
            Self::Replace(value) => value,
            Self::And(mask) => original & mask,
            Self::Or(mask) => original | mask,
        }
    }
}
pub(in super::super) fn mutations() -> impl Iterator<Item = Mutation> {
    (1u8..=255)
        .map(Mutation::Xor)
        .chain((0u8..=255).map(Mutation::Replace))
        .chain((0u8..=255).map(Mutation::And))
        .chain((0u8..=255).map(Mutation::Or))
}
std::thread_local! {
    static ACTION: Cell<Option<(Stage, Action)>> = const { Cell::new(None) };
    static HITS: Cell<usize> = const { Cell::new(0) };
}
pub(in super::super) struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        ACTION.set(None);
    }
}
pub(in super::super) fn inject(action: Action) -> Reset {
    inject_at(Stage::AfterFirst, action)
}
pub(in super::super) fn inject_at(stage: Stage, action: Action) -> Reset {
    assert!(ACTION.get().is_none());
    ACTION.set(Some((stage, action)));
    HITS.set(0);
    Reset
}
pub(in super::super) fn hits() -> usize {
    HITS.get()
}
pub(super) fn checkpoint(stage: Stage, replica: &mut [u8]) -> Result<(), Error> {
    if let Some((selected, action)) = ACTION.get()
        && stage == selected
    {
        HITS.set(HITS.get().wrapping_add(1));
        match action {
            Action::Flip(position) => *replica.get_mut(position).ok_or(Error::SecretMemory)? ^= 1,
            Action::Mutate(position, mutation) => {
                let byte = replica.get_mut(position).ok_or(Error::SecretMemory)?;
                *byte = mutation.apply(*byte);
            }
            Action::Error => return Err(Error::SecretMemory),
            Action::Unwind => resume_unwind(Box::new(())),
        }
    }
    Ok(())
}

mod matrix_tests;

#[test]
fn second_capture_uses_original_source_not_changed_first_replica() -> Result<(), Error> {
    for len in [16, 24, 32] {
        for position in 0..len {
            let input = [0x42; 32];
            let mut first = [0; 32];
            let mut second = [0; 32];
            let reset = inject(Action::Flip(position));
            pair(
                input.get(..len).ok_or(Error::SecretMemory)?,
                first.get_mut(..len).ok_or(Error::SecretMemory)?,
                second.get_mut(..len).ok_or(Error::SecretMemory)?,
            )?;
            assert_eq!(hits(), 1);
            drop(reset);
            assert_ne!(first.get(..len), second.get(..len));
            assert_eq!(second.get(..len), input.get(..len));
        }
    }
    Ok(())
}

#[test]
fn capture_error_and_unwind_keep_cleanup_with_the_caller_guard() {
    for action in [Action::Error, Action::Unwind] {
        let reset = inject(action);
        let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
            let mut first = super::super::Scratch::<16>::new();
            let mut second = super::super::Scratch::<16>::new();
            pair(&[0x42; 16], &mut first.0, &mut second.0)
        }));
        assert_eq!(hits(), 1);
        drop(reset);
        if matches!(action, Action::Unwind) {
            assert!(result.is_err());
        } else {
            assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
        }
        // Scratch Drop's existing observer checks zeroed live memory.
    }
}
