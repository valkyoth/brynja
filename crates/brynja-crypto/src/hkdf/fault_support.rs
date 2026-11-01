//! Test-only, thread-local fault control shared by the two HKDF unit harnesses.
//! No production module or external callback can access these controls.

extern crate std;
use std::{
    boxed::Box,
    cell::RefCell,
    panic::{AssertUnwindSafe, catch_unwind},
    vec,
    vec::Vec,
};

#[derive(Clone, Copy)]
enum Mode {
    None,
    Error(usize),
    Unwind(usize),
    ScratchUnwind,
}

struct Control {
    mode: Mode,
    steps: usize,
    // Observe while storage is still live, inside Drop after volatile clearing.
    // No secret values, raw pointers or reads of deallocated stack memory.
    scratch: Vec<(usize, bool, bool)>,
}

std::thread_local! {
    static CONTROL: RefCell<Control> = const { RefCell::new(Control {
        mode: Mode::None, steps: 0, scratch: Vec::new(),
    }) };
}

fn reset(mode: Mode) {
    CONTROL.with(|control| {
        *control.borrow_mut() = Control {
            mode,
            steps: 0,
            scratch: Vec::new(),
        }
    });
}

// Disable an armed fault even if an assertion fails, so subsequent tests are independent.
struct Disarm;
impl Drop for Disarm {
    fn drop(&mut self) {
        CONTROL.with(|c| c.borrow_mut().mode = Mode::None);
    }
}

pub(super) fn checkpoint() -> Result<(), ()> {
    let mode = CONTROL.with(|control| {
        let mut control = control.borrow_mut();
        control.steps = control.steps.saturating_add(1);
        match control.mode {
            Mode::Error(n) | Mode::Unwind(n) if n == control.steps => control.mode,
            _ => Mode::None,
        }
    });
    match mode {
        Mode::Error(_) => Err(()),
        Mode::Unwind(_) => std::panic::resume_unwind(Box::new(())),
        _ => Ok(()),
    }
}

pub(super) fn observe_scratch(populated: bool, bytes: &[u8]) {
    CONTROL.with(|control| {
        control
            .borrow_mut()
            .scratch
            .push((bytes.len(), populated, bytes.iter().all(|b| *b == 0)))
    });
}

fn assert_cleared() {
    CONTROL.with(|control| assert!(control.borrow().scratch.iter().all(|(_, _, clear)| *clear)));
}

pub(super) fn saw_populated_scratch(size: usize) -> bool {
    CONTROL.with(|control| {
        control
            .borrow()
            .scratch
            .iter()
            .any(|(n, populated, cleared)| *n == size && *populated && *cleared)
    })
}

pub(super) fn exercise<E: std::fmt::Debug>(
    length: usize,
    expected_steps: usize,
    mut operation: impl FnMut(&mut [u8]) -> Result<(), E>,
) -> Result<(), E> {
    let _disarm = Disarm;
    reset(Mode::None);
    let mut output = vec![0xa5; length];
    operation(&mut output)?;
    assert!(output.iter().all(|b| *b == 0));
    CONTROL.with(|control| assert_eq!(control.borrow().steps, expected_steps));
    assert_cleared();
    for at in 1..=expected_steps {
        for mode in [Mode::Error(at), Mode::Unwind(at)] {
            reset(mode);
            output.fill(0xa5);
            let result = catch_unwind(AssertUnwindSafe(|| operation(&mut output)));
            match mode {
                Mode::Error(_) => assert!(matches!(result, Ok(Err(_)))),
                Mode::Unwind(_) => assert!(result.is_err()),
                _ => unreachable!(),
            }
            CONTROL.with(|control| assert_eq!(control.borrow().steps, at));
            assert!(
                output.iter().all(|b| *b == 0),
                "partial output survived an injected interruption"
            );
            assert_cleared();
        }
    }
    // Retain observations from the final interruption for explicit scratch assertions.
    CONTROL.with(|control| control.borrow_mut().mode = Mode::None);
    Ok(())
}

pub(super) fn unwind_if_requested() {
    let requested = CONTROL.with(|control| matches!(control.borrow().mode, Mode::ScratchUnwind));
    if requested {
        std::panic::resume_unwind(Box::new(()));
    }
}

pub(super) fn exercise_scratch(mut operation: impl FnMut(), size: usize) {
    let _disarm = Disarm;
    for mode in [Mode::None, Mode::ScratchUnwind] {
        reset(mode);
        let result = catch_unwind(AssertUnwindSafe(&mut operation));
        assert_eq!(result.is_err(), matches!(mode, Mode::ScratchUnwind));
        assert_cleared();
        assert!(saw_populated_scratch(size));
    }
}
