//! Wall and monotonic clock contract tests.

use brynja_core::{
    ClockDuration, ClockGeneration, ClockUnavailable, DeadlineStatus, MonotonicClock,
    MonotonicClockError, MonotonicClockSource, MonotonicDeadline, MonotonicPurpose,
    NANOS_PER_SECOND, TimeError, WallClockSource, WallTime, WallTimeRange, WallTimeStatus,
};

fn duration(seconds: u64, nanoseconds: u32) -> ClockDuration {
    match ClockDuration::from_parts(seconds, nanoseconds) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    }
}

fn wall(seconds: i64, nanoseconds: u32) -> WallTime {
    match WallTime::from_unix_parts(seconds, nanoseconds) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    }
}

fn generation(value: u64) -> ClockGeneration {
    match ClockGeneration::new(value) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    }
}

struct Script<'a> {
    values: &'a [Result<u64, ClockUnavailable>],
    cursor: usize,
}

impl MonotonicClockSource for Script<'_> {
    fn read_monotonic_ticks(&mut self) -> Result<u64, ClockUnavailable> {
        let value = self
            .values
            .get(self.cursor)
            .copied()
            .ok_or(ClockUnavailable)?;
        self.cursor = self.cursor.checked_add(1).ok_or(ClockUnavailable)?;
        value
    }
}

struct WallScript(Result<WallTime, ClockUnavailable>);

impl WallClockSource for WallScript {
    fn read_wall_time(&mut self) -> Result<WallTime, ClockUnavailable> {
        self.0
    }
}

#[test]
fn duration_is_canonical_and_checked() {
    assert_eq!(
        ClockDuration::from_parts(0, NANOS_PER_SECOND),
        Err(TimeError::InvalidNanosecond)
    );
    assert!(ClockDuration::ZERO.is_zero());
    let carried = duration(1, 900_000_000).checked_add(duration(2, 200_000_000));
    assert_eq!(carried, Ok(duration(4, 100_000_000)));
    assert_eq!(
        duration(u64::MAX, 999_999_999).checked_add(duration(0, 1)),
        Err(TimeError::Overflow)
    );
    assert_eq!(
        duration(4, 100_000_000).checked_sub(duration(2, 200_000_000)),
        Ok(duration(1, 900_000_000))
    );
    assert_eq!(
        duration(0, 0).checked_sub(duration(0, 1)),
        Err(TimeError::Underflow)
    );
}

#[test]
fn wall_time_handles_epoch_and_arithmetic_boundaries() {
    assert_eq!(
        WallTime::from_unix_parts(0, NANOS_PER_SECOND),
        Err(TimeError::InvalidNanosecond)
    );
    let before_epoch = wall(-1, 900_000_000);
    assert_eq!(
        before_epoch.checked_add(duration(0, 200_000_000)),
        Ok(wall(0, 100_000_000))
    );
    assert_eq!(
        wall(0, 100_000_000).checked_sub(duration(0, 200_000_000)),
        Ok(before_epoch)
    );
    assert_eq!(
        wall(i64::MAX, 999_999_999).checked_add(duration(0, 1)),
        Err(TimeError::Overflow)
    );
    assert_eq!(
        wall(i64::MIN, 0).checked_sub(duration(0, 1)),
        Err(TimeError::Underflow)
    );
    assert_eq!(
        wall(3, 100).duration_since(wall(1, 200)),
        Ok(duration(1, 999_999_900))
    );
    assert_eq!(
        wall(1, 0).duration_since(wall(2, 0)),
        Err(TimeError::Underflow)
    );
}

#[test]
fn wall_ranges_are_ordered_inclusive_and_explicit() {
    assert_eq!(
        WallTimeRange::new(wall(2, 0), wall(1, 0)),
        Err(TimeError::ReversedRange)
    );
    let range = match WallTimeRange::new(wall(1, 0), wall(2, 0)) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    };
    assert_eq!(range.evaluate(wall(0, 999_999_999)), WallTimeStatus::Before);
    assert_eq!(range.evaluate(wall(1, 0)), WallTimeStatus::Valid);
    assert_eq!(range.evaluate(wall(2, 0)), WallTimeStatus::Valid);
    assert_eq!(range.evaluate(wall(2, 1)), WallTimeStatus::After);

    let mut unavailable = WallScript(Err(ClockUnavailable));
    assert_eq!(unavailable.read_wall_time(), Err(ClockUnavailable));
}

#[test]
fn generations_are_nonzero_and_exhaust_without_reuse() {
    assert_eq!(ClockGeneration::new(0), Err(TimeError::ZeroGeneration));
    assert_eq!(generation(1).next(), Ok(generation(2)));
    assert_eq!(generation(u64::MAX).next(), Err(TimeError::Overflow));
}

#[test]
fn monotonic_reads_allow_equality_and_make_rollback_terminal() {
    let script = [Ok(7), Ok(7), Err(ClockUnavailable), Ok(6), Ok(9)];
    let mut clock = MonotonicClock::new(
        Script {
            values: &script,
            cursor: 0,
        },
        generation(1),
    );
    assert!(clock.read().is_ok());
    assert!(clock.read().is_ok());
    assert_eq!(clock.read(), Err(MonotonicClockError::Unavailable));
    assert!(!clock.is_failed());
    assert_eq!(clock.read(), Err(MonotonicClockError::Regressed));
    assert!(clock.is_failed());
    assert_eq!(clock.read(), Err(MonotonicClockError::Failed));
}

#[test]
fn elapsed_time_rejects_direction_and_generation_confusion() {
    let first_script = [Ok(10), Ok(1_000_000_020)];
    let mut first = MonotonicClock::new(
        Script {
            values: &first_script,
            cursor: 0,
        },
        generation(4),
    );
    let start = first.read().unwrap_or_else(|_| unreachable!());
    let end = first.read().unwrap_or_else(|_| unreachable!());
    assert_eq!(end.elapsed_since(start), Ok(duration(1, 10)));
    assert_eq!(start.elapsed_since(end), Err(TimeError::Underflow));

    let second_script = [Ok(1_000_000_020)];
    let mut second = MonotonicClock::new(
        Script {
            values: &second_script,
            cursor: 0,
        },
        generation(5),
    );
    let other = second.read().unwrap_or_else(|_| unreachable!());
    assert_eq!(end.elapsed_since(other), Err(TimeError::GenerationMismatch));
}

#[test]
fn deadlines_bind_generation_purpose_and_checked_duration() {
    let script = [Ok(10), Ok(19), Ok(20), Ok(21)];
    let mut clock = MonotonicClock::new(
        Script {
            values: &script,
            cursor: 0,
        },
        generation(9),
    );
    let start = clock.read().unwrap_or_else(|_| unreachable!());
    let deadline = MonotonicDeadline::new(start, duration(0, 10), MonotonicPurpose::Replay)
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(deadline.require_purpose(MonotonicPurpose::Replay), Ok(()));
    assert_eq!(
        deadline.require_purpose(MonotonicPurpose::Ticket),
        Err(TimeError::PurposeMismatch)
    );
    let pending = clock.read().unwrap_or_else(|_| unreachable!());
    assert_eq!(
        deadline.evaluate(pending, MonotonicPurpose::Ticket),
        Err(TimeError::PurposeMismatch)
    );
    assert_eq!(
        deadline.evaluate(pending, MonotonicPurpose::Replay),
        Ok(DeadlineStatus::Pending(duration(0, 1)))
    );
    let exact = clock.read().unwrap_or_else(|_| unreachable!());
    assert_eq!(
        deadline.evaluate(exact, MonotonicPurpose::Replay),
        Ok(DeadlineStatus::Reached)
    );
    let late = clock.read().unwrap_or_else(|_| unreachable!());
    assert_eq!(
        deadline.evaluate(late, MonotonicPurpose::Replay),
        Ok(DeadlineStatus::Reached)
    );

    let other_script = [Ok(20)];
    let mut other = MonotonicClock::new(
        Script {
            values: &other_script,
            cursor: 0,
        },
        generation(10),
    );
    assert_eq!(
        deadline.evaluate(
            other.read().unwrap_or_else(|_| unreachable!()),
            MonotonicPurpose::Replay
        ),
        Err(TimeError::GenerationMismatch)
    );
}

#[test]
fn deadlines_reject_tick_and_duration_overflow() {
    let script = [Ok(u64::MAX)];
    let mut clock = MonotonicClock::new(
        Script {
            values: &script,
            cursor: 0,
        },
        generation(2),
    );
    let start = clock.read().unwrap_or_else(|_| unreachable!());
    assert!(matches!(
        MonotonicDeadline::new(start, duration(0, 1), MonotonicPurpose::Timer),
        Err(TimeError::Overflow)
    ));
    assert!(matches!(
        MonotonicDeadline::new(
            start,
            ClockDuration::from_seconds(u64::MAX),
            MonotonicPurpose::Freshness
        ),
        Err(TimeError::DurationTooLarge)
    ));
}
