//! Explicit source-evidence instrumentation only; never enabled by a Cargo feature.
extern crate std;
use super::super::capture::evidence_tests as capture;
use super::super::schedule::evidence_tests as round_skip;
use super::*;
use core::cell::Cell;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

mod capture_matrix_tests;

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Stage {
    Import,
    Before,
    AfterPrimary,
    AfterCompute,
}
#[derive(Clone, Copy)]
enum Site {
    PrimaryKey,
    SecondaryKey,
    PrimarySchedule,
    SecondarySchedule,
    Rounds,
}
#[derive(Clone, Copy)]
enum Action {
    Corrupt(Site, usize),
    Error,
    Unwind,
}
std::thread_local! {
    static PLAN: Cell<Option<(Stage,Action)>> = const { Cell::new(None) };
    static HITS: Cell<usize> = const { Cell::new(0) };
    static VISITS: Cell<usize> = const { Cell::new(0) };
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
    VISITS.set(0);
    Reset
}

fn change(owner: &mut Retained<'_>, site: Site, position: usize) -> Result<(), Error> {
    let byte = match site {
        Site::PrimaryKey => owner.keys.primary.get_mut(position),
        Site::SecondaryKey => owner.keys.complemented.get_mut(position),
        Site::PrimarySchedule => owner.primary.bytes().get_mut(position),
        Site::SecondarySchedule => owner
            .secondary
            .keys
            .get_mut(position / 16)
            .and_then(|p| p.0.0.get_mut(position % 16)),
        Site::Rounds => {
            owner.secondary.rounds ^= 1;
            return Ok(());
        }
    }
    .ok_or(Error::SecretMemory)?;
    *byte ^= 1;
    Ok(())
}

pub(super) fn checkpoint(stage: Stage, owner: &mut Retained<'_>) -> Result<(), Error> {
    VISITS.set(VISITS.get().wrapping_add(1));
    if let Some((selected, action)) = PLAN.get()
        && stage == selected
    {
        HITS.set(HITS.get().wrapping_add(1));
        match action {
            Action::Corrupt(site, position) => change(owner, site, position)?,
            Action::Error => return Err(Error::SecretMemory),
            Action::Unwind => resume_unwind(Box::new(())),
        }
    }
    Ok(())
}

fn run(owner: &mut Cached<'_>, path: usize, output: &mut [u8; 16]) -> Result<(), Error> {
    if path == 0 {
        owner.encrypt_public(&[0x24; 16], output, PublicCiphertext::acknowledge())
    } else {
        owner
            .secret(&[0x24; 16], output, path == 2)
            .map(|block| block.clear())
    }
}

fn run_ephemeral(
    owner: &mut ephemeral::Ephemeral<'_>,
    path: usize,
    output: &mut [u8; 16],
) -> Result<(), Error> {
    if path == 0 {
        owner.encrypt_public(&[0x24; 16], output, PublicCiphertext::acknowledge())
    } else {
        owner
            .secret(&[0x24; 16], output, path == 2)
            .map(|block| block.clear())
    }
}

#[test]
fn every_secondary_substitution_step_skip_retires_without_release() -> Result<(), Error> {
    // One declared source-level S1 call-site skip per execution. The existing
    // secondary engine and real owner/transaction must reject its disagreement
    // with the independent primary. This is not an instruction-skip experiment.
    for width in [16usize, 24, 32] {
        let rounds = width / 4 + 6;
        let key = [0x42; 32];
        for path in 0..3 {
            let inverse = path == 2;
            for step in 1..=rounds {
                for ephemeral in [false, true] {
                    let mut a = [0x91; 32];
                    let mut b = [0x92; 32];
                    let mut output = [0x93; 16];
                    if ephemeral {
                        let mut owner = ephemeral::Ephemeral::new(
                            key.get(..width).ok_or(Error::SecretMemory)?,
                            a.get_mut(..width).ok_or(Error::SecretMemory)?,
                            b.get_mut(..width).ok_or(Error::SecretMemory)?,
                        )?;
                        let reset = round_skip::plan(step, inverse);
                        assert!(run_ephemeral(&mut owner, path, &mut output).is_err());
                        assert_eq!(round_skip::hits(), 1);
                        drop(reset);
                        assert_eq!(output, if path == 0 { [0x93; 16] } else { [0; 16] });
                        assert!(run_ephemeral(&mut owner, path, &mut output).is_err());
                    } else {
                        let mut owner = Cached::new(
                            key.get(..width).ok_or(Error::SecretMemory)?,
                            a.get_mut(..width).ok_or(Error::SecretMemory)?,
                            b.get_mut(..width).ok_or(Error::SecretMemory)?,
                        )?;
                        let reset = round_skip::plan(step, inverse);
                        assert!(run(&mut owner, path, &mut output).is_err());
                        assert_eq!(round_skip::hits(), 1);
                        drop(reset);
                        assert_eq!(output, if path == 0 { [0x93; 16] } else { [0; 16] });
                        assert!(run(&mut owner, path, &mut output).is_err());
                    }
                    assert!(
                        a.get(..width)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0)
                    );
                    assert!(
                        b.get(..width)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0)
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn operation_local_import_capture_failure_clears_both_admitted_keys() -> Result<(), Error> {
    for width in [16usize, 24, 32] {
        for action in [
            capture::Action::Flip(width.wrapping_sub(1)),
            capture::Action::Error,
            capture::Action::Unwind,
        ] {
            let key = [0x42; 32];
            let mut a = [0x91; 32];
            let mut b = [0x92; 32];
            let reset = capture::inject(action);
            crate::aes::tests::take_cleared_regions();
            let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
                let _owner = ephemeral::Ephemeral::new(
                    key.get(..width).ok_or(Error::SecretMemory)?,
                    a.get_mut(..width).ok_or(Error::SecretMemory)?,
                    b.get_mut(..width).ok_or(Error::SecretMemory)?,
                )?;
                Ok(())
            }));
            assert_eq!(capture::hits(), 1);
            drop(reset);
            if matches!(action, capture::Action::Unwind) {
                assert!(result.is_err());
            } else {
                assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
            }
            assert_eq!(crate::aes::tests::take_cleared_regions() & (1 | 8 | 16), 0);
            for (storage, sentinel) in [(&a, 0x91), (&b, 0x92)] {
                assert!(
                    storage
                        .get(..width)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|v| *v == 0)
                );
                assert!(
                    storage
                        .get(width..)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|v| *v == sentinel)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn operation_local_schedule_failures_clear_temporaries_and_retire() -> Result<(), Error> {
    for (width, schedule_bit) in [(16usize, 1), (24, 8), (32, 16)] {
        for stage in [
            Stage::Import,
            Stage::Before,
            Stage::AfterPrimary,
            Stage::AfterCompute,
        ] {
            for action in [
                Action::Corrupt(Site::PrimaryKey, width.wrapping_sub(1)),
                Action::Corrupt(Site::SecondaryKey, 0),
                Action::Corrupt(Site::PrimarySchedule, 0),
                Action::Corrupt(Site::SecondarySchedule, 239),
                Action::Corrupt(Site::Rounds, 0),
                Action::Error,
                Action::Unwind,
            ] {
                for path in 0..3 {
                    let key = [0x42; 32];
                    let mut a = [0x91; 32];
                    let mut b = [0x92; 32];
                    let reset = plan(stage, action);
                    let mut owner = ephemeral::Ephemeral::new(
                        key.get(..width).ok_or(Error::SecretMemory)?,
                        a.get_mut(..width).ok_or(Error::SecretMemory)?,
                        b.get_mut(..width).ok_or(Error::SecretMemory)?,
                    )?;
                    // Import retains raw key replicas but expands no schedule.
                    assert_eq!(VISITS.get(), 0);
                    crate::aes::tests::take_cleared_regions();
                    let mut output = [0x91; 16];
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        run_ephemeral(&mut owner, path, &mut output)
                    }));
                    assert_eq!(HITS.get(), 1);
                    drop(reset);
                    if matches!(action, Action::Unwind) {
                        assert!(result.is_err());
                    } else {
                        assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
                    }
                    assert_eq!(output, if path == 0 { [0x91; 16] } else { [0; 16] });
                    assert_ne!(crate::aes::tests::take_cleared_regions() & schedule_bit, 0);
                    let reset = plan(Stage::Import, Action::Unwind);
                    for retry in 0..3 {
                        assert!(run_ephemeral(&mut owner, retry, &mut output).is_err());
                    }
                    assert_eq!(VISITS.get(), 0);
                    drop(reset);
                    drop(owner);
                    for storage in [&a, &b] {
                        assert!(
                            storage
                                .get(..width)
                                .ok_or(Error::SecretMemory)?
                                .iter()
                                .all(|v| *v == 0)
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn operation_local_input_capture_failures_retire_and_clear_schedules() -> Result<(), Error> {
    for (width, schedule_bit) in [(16usize, 1), (24, 8), (32, 16)] {
        for action in [
            capture::Action::Flip(15),
            capture::Action::Error,
            capture::Action::Unwind,
        ] {
            for path in 0..3 {
                let key = [0x42; 32];
                let mut a = [0; 32];
                let mut b = [0; 32];
                let mut owner = ephemeral::Ephemeral::new(
                    key.get(..width).ok_or(Error::SecretMemory)?,
                    a.get_mut(..width).ok_or(Error::SecretMemory)?,
                    b.get_mut(..width).ok_or(Error::SecretMemory)?,
                )?;
                let mut output = [0x91; 16];
                crate::aes::tests::take_cleared_regions();
                let reset = capture::inject(action);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    run_ephemeral(&mut owner, path, &mut output)
                }));
                assert_eq!(capture::hits(), 1);
                drop(reset);
                if matches!(action, capture::Action::Unwind) {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
                }
                assert_eq!(output, if path == 0 { [0x91; 16] } else { [0; 16] });
                assert_ne!(crate::aes::tests::take_cleared_regions() & schedule_bit, 0);
                let reset = capture::inject(capture::Action::Unwind);
                for retry in 0..3 {
                    assert!(run_ephemeral(&mut owner, retry, &mut output).is_err());
                }
                assert_eq!(capture::hits(), 0);
                drop(reset);
            }
        }
    }
    Ok(())
}

#[test]
fn interrupted_key_capture_clears_and_input_capture_retires() -> Result<(), Error> {
    for width in [16usize, 24, 32] {
        for action in [
            capture::Action::Flip(width.wrapping_sub(1)),
            capture::Action::Error,
            capture::Action::Unwind,
        ] {
            let key = [0x42; 32];
            let mut a = [0x91; 32];
            let mut b = [0x92; 32];
            let reset = capture::inject(action);
            let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
                let _owner = Cached::new(
                    key.get(..width).ok_or(Error::SecretMemory)?,
                    a.get_mut(..width).ok_or(Error::SecretMemory)?,
                    b.get_mut(..width).ok_or(Error::SecretMemory)?,
                )?;
                Ok(())
            }));
            assert_eq!(capture::hits(), 1);
            drop(reset);
            if matches!(action, capture::Action::Unwind) {
                assert!(result.is_err());
            } else {
                assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
            }
            assert!(
                a.get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|v| *v == 0)
            );
            assert!(
                b.get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|v| *v == 0)
            );
        }
        for action in [
            capture::Action::Flip(15),
            capture::Action::Error,
            capture::Action::Unwind,
        ] {
            for path in 0..3 {
                let key = [0x42; 32];
                let mut a = [0; 32];
                let mut b = [0; 32];
                let mut owner = Cached::new(
                    key.get(..width).ok_or(Error::SecretMemory)?,
                    a.get_mut(..width).ok_or(Error::SecretMemory)?,
                    b.get_mut(..width).ok_or(Error::SecretMemory)?,
                )?;
                let mut output = [0x91; 16];
                let reset = capture::inject(action);
                let result = catch_unwind(AssertUnwindSafe(|| run(&mut owner, path, &mut output)));
                assert_eq!(capture::hits(), 1);
                drop(reset);
                if matches!(action, capture::Action::Unwind) {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
                }
                assert_eq!(output, if path == 0 { [0x91; 16] } else { [0; 16] });
                let reset = capture::inject(capture::Action::Unwind);
                for retry in 0..3 {
                    assert!(run(&mut owner, retry, &mut output).is_err());
                }
                assert_eq!(capture::hits(), 0);
                drop(reset);
            }
        }
    }
    Ok(())
}

#[test]
fn every_retained_byte_and_round_count_are_checked_without_repair() -> Result<(), Error> {
    for width in [16, 24, 32] {
        let key = [0x42; 32];
        let mut a = [0; 32];
        let mut b = [0; 32];
        let mut owner = Retained::new(
            key.get(..width).ok_or(Error::SecretMemory)?,
            a.get_mut(..width).ok_or(Error::SecretMemory)?,
            b.get_mut(..width).ok_or(Error::SecretMemory)?,
        )?;
        for (site, len) in [
            (Site::PrimaryKey, width),
            (Site::SecondaryKey, width),
            (Site::PrimarySchedule, owner.primary.as_bytes().len()),
            (Site::SecondarySchedule, 240),
            (Site::Rounds, 1),
        ] {
            for position in 0..len {
                change(&mut owner, site, position)?;
                assert!(owner.validate().is_err());
                assert!(owner.validate().is_err()); // Checking does not heal it.
                change(&mut owner, site, position)?; // New independent test trial.
                owner.validate()?;
            }
        }
    }
    Ok(())
}

#[test]
fn import_corruption_errors_and_unwinds_clear_both_keys() -> Result<(), Error> {
    for width in [16, 24, 32] {
        for action in [
            Action::Corrupt(Site::PrimaryKey, 0),
            Action::Corrupt(Site::SecondaryKey, 0),
            Action::Corrupt(Site::PrimarySchedule, 0),
            Action::Corrupt(Site::SecondarySchedule, 239),
            Action::Corrupt(Site::Rounds, 0),
            Action::Error,
            Action::Unwind,
        ] {
            let key = [0x42; 32];
            let mut a = [0x91; 32];
            let mut b = [0x92; 32];
            let reset = plan(Stage::Import, action);
            let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
                let _owner = Cached::new(
                    key.get(..width).ok_or(Error::SecretMemory)?,
                    a.get_mut(..width).ok_or(Error::SecretMemory)?,
                    b.get_mut(..width).ok_or(Error::SecretMemory)?,
                )?;
                Ok(())
            }));
            assert_eq!(HITS.get(), 1);
            drop(reset);
            if matches!(action, Action::Unwind) {
                assert!(result.is_err());
            } else {
                assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
            }
            assert!(
                a.get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|v| *v == 0)
            );
            assert!(
                b.get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|v| *v == 0)
            );
        }
    }
    Ok(())
}

#[test]
fn failures_at_each_stage_retire_before_any_output_release() -> Result<(), Error> {
    for width in [16usize, 24, 32] {
        for stage in [Stage::Before, Stage::AfterPrimary, Stage::AfterCompute] {
            for action in [
                Action::Corrupt(Site::PrimaryKey, width.wrapping_sub(1)),
                Action::Corrupt(Site::SecondaryKey, 0),
                Action::Corrupt(Site::PrimarySchedule, 0),
                Action::Corrupt(Site::SecondarySchedule, 239),
                Action::Corrupt(Site::Rounds, 0),
                Action::Error,
                Action::Unwind,
            ] {
                for path in 0..3 {
                    let key = [0x42; 32];
                    let mut a = [0; 32];
                    let mut b = [0; 32];
                    let mut owner = Cached::new(
                        key.get(..width).ok_or(Error::SecretMemory)?,
                        a.get_mut(..width).ok_or(Error::SecretMemory)?,
                        b.get_mut(..width).ok_or(Error::SecretMemory)?,
                    )?;
                    let mut output = [0x91; 16];
                    let reset = plan(stage, action);
                    let result =
                        catch_unwind(AssertUnwindSafe(|| run(&mut owner, path, &mut output)));
                    assert_eq!(HITS.get(), 1);
                    drop(reset);
                    if matches!(action, Action::Unwind) {
                        assert!(result.is_err());
                    } else {
                        assert_eq!(result.ok(), Some(Err(Error::SecretMemory)));
                    }
                    assert_eq!(output, if path == 0 { [0x91; 16] } else { [0; 16] });
                    let reset = plan(Stage::Before, Action::Unwind);
                    // All three entry paths must reject before any checkpoint.
                    for retry in 0..3 {
                        assert!(run(&mut owner, retry, &mut output).is_err());
                    }
                    assert_eq!(VISITS.get(), 0);
                    assert_eq!(HITS.get(), 0);
                    drop(reset);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn correlated_key_and_schedule_replacement_is_a_common_mode_control() -> Result<(), Error> {
    let mut a = [0; 16];
    let mut b = [0; 16];
    let mut owner = Cached::new(&[0x42; 16], &mut a, &mut b)?;
    let mut baseline = [0; 16];
    owner.encrypt_public(&[0x24; 16], &mut baseline, PublicCiphertext::acknowledge())?;
    // Four coordinated changes are outside the single-domain budget. It is NOT
    // legitimate application recovery; this demonstrates what validation trusts.
    owner.retained.keys.primary.fill(0x43);
    owner.retained.keys.complemented.fill(!0x43);
    owner.retained.primary.expand(&[0x43; 16])?;
    owner.retained.secondary.expand(&[0x43; 16])?;
    owner.retained.validate()?;
    let mut changed = [0; 16];
    owner.encrypt_public(&[0x24; 16], &mut changed, PublicCiphertext::acknowledge())?;
    assert_ne!(baseline, changed);
    Ok(())
}

#[test]
fn common_zero_key_capture_is_rejected_but_zeroing_both_schedules_is_not_universally_detected()
-> Result<(), Error> {
    let mut a = [0; 16];
    let mut b = [0; 16];
    let mut owner = Cached::new(&[0; 16], &mut a, &mut b)?;
    let mut baseline = [0; 16];
    owner.encrypt_public(&[0x24; 16], &mut baseline, PublicCiphertext::acknowledge())?;
    owner.retained.primary.bytes().fill(0);
    for plane in &mut owner.retained.secondary.keys {
        plane.0.0.fill(0);
    }
    // Bit-plane zero still decodes to zero. With a zero key prefix, two wiped
    // schedules agree and pass this check. This correlated event is excluded;
    // differing layouts alone must not be advertised as common-mode protection.
    owner.retained.validate()?;
    let mut changed = [0; 16];
    owner.encrypt_public(&[0x24; 16], &mut changed, PublicCiphertext::acknowledge())?;
    assert_ne!(baseline, changed);
    owner.retained.keys.primary.fill(0);
    owner.retained.keys.complemented.fill(0);
    assert!(owner.retained.validate().is_err()); // Complement relation is broken.
    Ok(())
}
