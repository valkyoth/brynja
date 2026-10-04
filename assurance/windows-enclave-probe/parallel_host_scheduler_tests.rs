use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn open(generation: u32, lanes: u8) -> u64 {
    (u64::from(generation) << 32) | (((1_u64 << lanes) - 1) << 12) | OPEN
}
fn complete(generation: u32, lanes: u8) -> u64 {
    let mask = (1_u64 << lanes) - 1;
    (u64::from(generation) << 32) | (mask << 12) | (mask << 8) | mask | CLOSED
}
fn retired(generation: u32) -> u64 {
    u64::from(generation) << 32
}
fn ready_to_close() -> Scheduler {
    let mut s = Scheduler::new(32, 1).unwrap();
    s.dispatch(open(1, 4), &|_| Ok(())).unwrap();
    s
}
fn ready_to_complete() -> Scheduler {
    let mut s = ready_to_close();
    s.closed().unwrap();
    s
}
fn ready_to_retire() -> Scheduler {
    let mut s = ready_to_complete();
    s.complete(complete(1, 4)).unwrap();
    s
}
fn terminal(s: &mut Scheduler) {
    assert_eq!(
        s.dispatch(open(1, 4), &|_| panic!("terminal dispatch")),
        Err(Error::Quarantined)
    );
}

#[test]
fn variable_waves_exact_lanes_join_and_empty() {
    for leaves in (0..=17).chain([129]) {
        let bits = if leaves == 0 { 0 } else { leaves * 56 - 3 };
        let mut s = Scheduler::new(bits, 7).unwrap();
        let mut generations = 0;
        let mask = AtomicUsize::new(0);
        while u64::from(generations) < leaves.div_ceil(4) {
            let lanes = (leaves - u64::from(generations) * 4).min(4) as u8;
            generations += 1;
            mask.store(0, Ordering::SeqCst);
            let barrier = std::sync::Barrier::new(usize::from(lanes));
            s.dispatch(open(generations, lanes), &|work| {
                assert_eq!(work.generation, generations);
                assert_eq!(
                    work.word(),
                    u64::from(generations) * 16 + u64::from(work.lane)
                );
                assert!(work.lane < lanes);
                barrier.wait(); // all workers actually overlap, not sequential execution
                let bit = 1 << work.lane;
                assert_eq!(mask.fetch_or(bit, Ordering::SeqCst) & bit, 0);
                Ok(())
            })
            .unwrap();
            assert_eq!(mask.load(Ordering::SeqCst), (1 << lanes) - 1);
            s.closed().unwrap();
            s.complete(complete(generations, lanes)).unwrap();
        }
        assert_eq!(s.finish(retired(generations)), Ok(generations));
    }
}

#[test]
fn every_native_bit_is_checked_before_spawning() {
    for bit in 0..64 {
        let mut s = Scheduler::new(32, 1).unwrap();
        assert_eq!(
            s.dispatch(open(1, 4) ^ (1 << bit), &|_| panic!("invalid dispatch")),
            Err(Error::Protocol)
        );
        terminal(&mut s);
    }
}

#[test]
fn close_join_retire_are_ordered_and_one_shot() {
    let mut s = Scheduler::new(32, 1).unwrap();
    assert_eq!(s.closed(), Err(Error::Protocol));
    terminal(&mut s);
    let mut s = ready_to_close();
    assert_eq!(s.complete(complete(1, 4)), Err(Error::Protocol));
    terminal(&mut s);
    let mut s = ready_to_complete();
    assert_eq!(s.closed(), Err(Error::Protocol));
    terminal(&mut s);
    let mut s = ready_to_retire();
    assert_eq!(s.complete(complete(1, 4)), Err(Error::Protocol));
    terminal(&mut s);
    let mut s = ready_to_retire();
    assert_eq!(
        s.dispatch(open(1, 4), &|_| panic!("replay")),
        Err(Error::Protocol)
    );
    terminal(&mut s);
}

#[test]
fn every_completion_and_retirement_bit_is_checked() {
    for bit in 0..64 {
        let mut s = ready_to_complete();
        assert_eq!(
            s.complete(complete(1, 4) ^ (1 << bit)),
            Err(Error::Protocol)
        );
        terminal(&mut s);
        let s = ready_to_retire();
        assert_eq!(s.finish(retired(1) ^ (1 << bit)), Err(Error::Protocol));
    }
}

#[test]
fn failures_and_panics_join_every_started_worker() {
    for failing in 0..4 {
        for panic in [false, true] {
            let mut s = Scheduler::new(32, 1).unwrap();
            let done = AtomicUsize::new(0);
            let barrier = std::sync::Barrier::new(4);
            let result = s.dispatch(open(1, 4), &|work| {
                barrier.wait();
                if work.lane == failing {
                    if panic {
                        panic!("injected worker panic");
                    }
                    return Err(Error::Worker);
                }
                for _ in 0..100 {
                    std::thread::yield_now();
                }
                done.fetch_or(1 << work.lane, Ordering::SeqCst);
                Ok(())
            });
            assert_eq!(result, Err(Error::Worker));
            assert_eq!(done.load(Ordering::SeqCst), 15 ^ (1 << failing));
            terminal(&mut s);
        }
    }
}

#[test]
fn partial_spawn_and_root_unwind_join_before_borrow_returns() {
    for stop in 0..4 {
        for panic in [false, true] {
            let mut s = Scheduler::new(32, 1).unwrap();
            let done = AtomicUsize::new(0);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                s.dispatch_with(
                    open(1, 4),
                    &|work| {
                        for _ in 0..100 {
                            std::thread::yield_now();
                        }
                        done.fetch_or(1 << work.lane, Ordering::SeqCst);
                        Ok(())
                    },
                    |lane| {
                        if lane == stop {
                            if panic {
                                panic!("injected spawn unwind");
                            }
                            Err(Error::Spawn)
                        } else {
                            Ok(())
                        }
                    },
                )
            }));
            if panic {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Err(Error::Spawn));
            }
            assert_eq!(done.load(Ordering::SeqCst), (1 << stop) - 1);
            terminal(&mut s);
        }
    }
}

#[test]
fn bounds_and_maximum_generation_do_not_wrap() {
    for block in [0, 1025, u64::MAX] {
        assert!(matches!(Scheduler::new(0, block), Err(Error::Bounds)));
    }
    assert!(matches!(Scheduler::new(u64::MAX, 1), Err(Error::Bounds)));
    assert!(matches!(
        Scheduler::new(65536 * 8 + 1, 1),
        Err(Error::Bounds)
    ));
    let mut s = Scheduler::new(65536 * 8192, 1024).unwrap();
    s.completed = 16383; // boundary injection, not a maximum-size native run
    assert_eq!(s.next(), Ok((16384, 4, 15)));
    s.dispatch(open(16384, 4), &|_| Ok(())).unwrap();
    s.closed().unwrap();
    s.complete(complete(16384, 4)).unwrap();
    assert_eq!(s.finish(retired(16384)), Ok(16384));
}

#[test]
fn missing_wave_or_unretired_root_cannot_finish() {
    assert_eq!(
        Scheduler::new(1, 1).unwrap().finish(0),
        Err(Error::Protocol)
    );
    assert_eq!(ready_to_close().finish(0), Err(Error::Protocol));
    assert_eq!(ready_to_complete().finish(0), Err(Error::Protocol));
    assert_eq!(ready_to_retire().finish(0), Err(Error::Protocol));
    assert_eq!(
        Scheduler::new(0, 1).unwrap().finish(1),
        Err(Error::Protocol)
    );
    let mut s = Scheduler::new(0, 1).unwrap();
    assert_eq!(
        s.dispatch(open(1, 1), &|_| panic!("empty dispatch")),
        Err(Error::Protocol)
    );
    terminal(&mut s);
}
