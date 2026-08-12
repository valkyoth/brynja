//! Repository-only deterministic clock fixture tests.

use brynja_core::{
    ClockGeneration, ClockUnavailable, MonotonicClock, MonotonicClockError, WallClockSource,
    WallTime,
};
use brynja_test_support::{
    DeterministicMonotonicClock, DeterministicReading, DeterministicWallClock,
};

fn wall(seconds: i64) -> WallTime {
    match WallTime::from_unix_parts(seconds, 0) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    }
}

#[test]
fn deterministic_wall_clock_preserves_exact_script_and_unavailability() {
    let readings = [
        DeterministicReading::Value(wall(-1)),
        DeterministicReading::Unavailable,
        DeterministicReading::Value(wall(2)),
    ];
    let mut clock = DeterministicWallClock::new(&readings);
    assert_eq!(clock.read_wall_time(), Ok(wall(-1)));
    assert_eq!(clock.read_wall_time(), Err(ClockUnavailable));
    assert_eq!(clock.read_wall_time(), Ok(wall(2)));
    assert_eq!(clock.read_wall_time(), Err(ClockUnavailable));
    assert_eq!(clock.consumed(), 3);
}

#[test]
fn deterministic_monotonic_clock_exercises_rollback_and_exhaustion() {
    let readings = [
        DeterministicReading::Value(5),
        DeterministicReading::Unavailable,
        DeterministicReading::Value(4),
        DeterministicReading::Value(8),
    ];
    let source = DeterministicMonotonicClock::new(&readings);
    let generation = ClockGeneration::new(1).unwrap_or_else(|_| unreachable!());
    let mut clock = MonotonicClock::new(source, generation);
    assert!(clock.read().is_ok());
    assert_eq!(clock.read(), Err(MonotonicClockError::Unavailable));
    assert_eq!(clock.read(), Err(MonotonicClockError::Regressed));
    assert_eq!(clock.read(), Err(MonotonicClockError::Failed));
}
