use super::*;
use std::sync::Barrier;

#[test]
fn exact_generation_lane_and_one_shot_publication() {
    let gate = Gate::new();
    assert!(gate.reserve(0).is_none() && gate.reserve(5).is_none());
    assert!(gate.enter(1, 0).is_none());
    let mut wave = gate.reserve(2).unwrap();
    assert_eq!(wave.generation(), 1);
    assert!(!wave.quiescent() && !wave.retire());
    assert!(gate.enter(1, 0).is_none());
    assert!(gate.reserve(1).is_none());
    assert!(wave.publish() && !wave.publish());
    assert!(!wave.quiescent() && !wave.retire());
    for generation in [0, 2, u32::MAX] {
        assert!(gate.enter(generation, 0).is_none());
    }
    for lane in [2, 3, 4, usize::MAX] {
        assert!(gate.enter(1, lane).is_none());
    }
    let ticket = gate.enter(1, 0).unwrap();
    assert!(gate.enter(1, 0).is_none());
    ticket.succeeded();
    wave.close();
    assert!(!wave.publish());
    assert!(!wave.quiescent() && !wave.all_succeeded() && !wave.retire());
    assert!(gate.enter(1, 1).is_none());
    drop(ticket);
    assert!(wave.quiescent() && !wave.all_succeeded());
    assert!(wave.retire());
    assert!(!wave.retire() && !wave.publish() && !wave.quiescent() && !wave.all_succeeded());
    let next = gate.reserve(1).unwrap();
    assert_eq!(next.generation(), 2);
    assert!(next.publish());
    wave.close(); // A retired lease must not close a new publication.
    drop(wave);
    assert!(gate.enter(2, 0).is_some());
}

#[test]
fn empty_closed_wave_cannot_reopen() {
    let gate = Gate::new();
    let mut wave = gate.reserve(4).unwrap();
    assert!(wave.publish());
    wave.close();
    assert!(wave.quiescent());
    assert!(!wave.publish() && !wave.all_succeeded());
    assert!(gate.enter(1, 0).is_none());
    assert!(wave.retire());
}

#[test]
fn retired_generation_rejects_during_next_open_wave() {
    let gate = Gate::new();
    let mut old = gate.reserve(4).unwrap();
    assert!(old.publish());
    old.close();
    assert!(old.retire());
    let next = gate.reserve(4).unwrap();
    assert!(next.publish());
    for lane in 0..4 {
        assert!(gate.enter(old.generation(), lane).is_none());
        gate.enter(next.generation(), lane).unwrap().succeeded();
    }
    next.close();
    assert!(next.all_succeeded());
}

#[test]
fn abandoned_or_unwound_root_seals_gate() {
    for panic in [false, true] {
        let gate = Gate::new();
        let result = std::panic::catch_unwind(|| {
            let wave = gate.reserve(1).unwrap();
            assert!(wave.publish());
            if panic {
                panic!("synthetic root unwind");
            }
        });
        assert_eq!(result.is_err(), panic);
        assert!(gate.enter(1, 0).is_none() && gate.reserve(1).is_none());
    }
}

#[test]
fn incomplete_or_unwound_workers_never_commit() {
    for lanes in 1..=4 {
        let gate = Gate::new();
        let mut wave = gate.reserve(lanes).unwrap();
        assert!(wave.publish());
        let result = std::panic::catch_unwind(|| {
            let _ticket = gate.enter(1, 0).unwrap();
            panic!("synthetic worker unwind");
        });
        assert!(result.is_err());
        for lane in 1..lanes {
            gate.enter(1, lane).unwrap().succeeded();
        }
        wave.close();
        assert!(wave.quiescent() && !wave.all_succeeded());
        assert!(wave.retire());
    }
}

#[test]
fn partial_waves_require_exact_success_and_release() {
    let gate = Gate::new();
    for lanes in 1..=4 {
        let mut wave = gate.reserve(lanes).unwrap();
        assert!(wave.publish());
        let tickets: std::vec::Vec<_> = (0..lanes)
            .map(|lane| gate.enter(wave.generation(), lane).unwrap())
            .collect();
        for ticket in &tickets {
            ticket.succeeded();
        }
        assert!(!wave.all_succeeded());
        wave.close();
        assert!(!wave.all_succeeded() && !wave.retire());
        drop(tickets);
        assert!(wave.quiescent() && wave.all_succeeded());
        assert!(wave.retire());
    }
}

#[test]
fn generation_exhaustion_never_wraps_or_reauthorizes() {
    let gate = Gate(AtomicU64::new(u64::from(u32::MAX - 1) << 32));
    let mut wave = gate.reserve(1).unwrap();
    assert_eq!(wave.generation(), u32::MAX);
    assert!(wave.publish());
    gate.enter(u32::MAX, 0).unwrap().succeeded();
    wave.close();
    assert!(wave.all_succeeded() && wave.retire());
    assert!(gate.reserve(1).is_none());
    assert!(gate.enter(0, 0).is_none() && gate.enter(1, 0).is_none());
}

#[test]
fn reserve_race_has_exactly_one_root() {
    for _ in 0..64 {
        let gate = Gate::new();
        let barrier = Barrier::new(4);
        std::thread::scope(|scope| {
            let handles: std::vec::Vec<_> = (0..4)
                .map(|_| {
                    let (gate, barrier) = (&gate, &barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        gate.reserve(1).is_some()
                    })
                })
                .collect();
            assert_eq!(
                handles
                    .into_iter()
                    .map(|h| usize::from(h.join().unwrap()))
                    .sum::<usize>(),
                1
            );
        });
    }
}

#[test]
fn delayed_workers_cannot_claim_reused_slots() {
    let gate = Gate::new();
    for _ in 0..128 {
        let mut old = gate.reserve(4).unwrap();
        let generation = old.generation();
        assert!(old.publish());
        let claimed = Barrier::new(5);
        let release = Barrier::new(5);
        let replay = Barrier::new(5);
        let replayed = Barrier::new(5);
        std::thread::scope(|scope| {
            for lane in 0..4 {
                let (gate, claimed, release, replay, replayed) =
                    (&gate, &claimed, &release, &replay, &replayed);
                scope.spawn(move || {
                    let ticket = gate.enter(generation, lane).unwrap();
                    ticket.succeeded();
                    claimed.wait();
                    release.wait();
                    drop(ticket);
                    replay.wait();
                    // A new wave is now live on the same gate; old request
                    // context must reject even if pointer addresses are reused.
                    assert!(gate.enter(generation, lane).is_none());
                    replayed.wait();
                });
            }
            claimed.wait();
            old.close();
            assert!(!old.quiescent() && !old.retire());
            assert!(gate.reserve(4).is_none());
            release.wait();
            while !old.quiescent() {
                std::thread::yield_now();
            }
            assert!(old.all_succeeded() && old.retire());
            let mut next = gate.reserve(4).unwrap();
            assert_eq!(next.generation(), generation + 1);
            assert!(next.publish());
            replay.wait();
            replayed.wait(); // All stale calls tested while next is open/unclaimed.
            for lane in 0..4 {
                gate.enter(next.generation(), lane).unwrap().succeeded();
            }
            next.close();
            assert!(next.all_succeeded() && next.retire());
        });
    }
}

#[test]
fn close_admission_races_claim_without_false_quiescence() {
    for _ in 0..128 {
        let gate = Gate::new();
        let mut wave = gate.reserve(4).unwrap();
        assert!(wave.publish());
        let start = Barrier::new(5);
        std::thread::scope(|scope| {
            for lane in 0..4 {
                let (gate, start) = (&gate, &start);
                scope.spawn(move || {
                    start.wait();
                    if let Some(ticket) = gate.enter(1, lane) {
                        ticket.succeeded();
                    }
                });
            }
            start.wait();
            wave.close();
            while !wave.quiescent() {
                std::thread::yield_now();
            }
            assert!(gate.enter(1, 0).is_none());
        });
        assert!(wave.retire());
    }
}
