use super::*;
use core::sync::atomic::AtomicUsize;
use std::sync::Barrier;
static ENTERED: AtomicUsize = AtomicUsize::new(0);
static HANDLES: std::sync::Mutex<std::vec::Vec<std::thread::JoinHandle<usize>>> =
    std::sync::Mutex::new(std::vec::Vec::new());

fn mode() -> std::string::String {
    std::env::var("BRYNJA_PRIVATE_PARALLEL_MODE").unwrap_or_else(|_| "normal".into())
}
pub fn after_claim() {
    if mode() == "early" {
        ENTERED.fetch_add(1, Ordering::Release);
        while GATE.accepting() {
            std::thread::yield_now();
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn PrivateParallelDispatch() -> usize {
    if mode() == "empty" {
        return 1;
    }
    if mode() == "early" {
        for lane in 0..4 {
            HANDLES.lock().unwrap().push(std::thread::spawn(move || {
                // SAFETY: the root stays live until enclave-side join completes.
                unsafe { PrivateParallelLeaf(lane) }
            }));
        }
        while ENTERED.load(Ordering::Acquire) != 4 {
            std::thread::yield_now();
        }
        // No host join: workers are deliberately still borrowing root storage.
        return 1;
    }
    std::thread::scope(|scope| {
        let mut handles = std::vec::Vec::new();
        for lane in 0..4 {
            handles.push(scope.spawn(move || {
                // SAFETY: ordinary-process diagnostic with native AVX2. Not
                // claiming residency; root publication remains live and joined.
                unsafe { PrivateParallelLeaf(lane) }
            }));
        }
        for handle in handles {
            assert_eq!(handle.join().unwrap(), 1);
        }
    });
    1
}
#[unsafe(no_mangle)]
extern "C" fn PrivateParallelAbort() -> ! {
    std::process::abort()
}
#[unsafe(no_mangle)]
extern "C" fn PrivateParallelRootRegion(_: usize, _: usize) -> usize {
    1
}

#[test]
fn native_bridge_oracle_and_one_shot_lifetime() {
    let identity = std::env::var("BRYNJA_PRIVATE_PARALLEL_ID")
        .unwrap()
        .parse()
        .unwrap();
    // SAFETY: host has AVX2; this test deliberately provides no residency claim.
    unsafe {
        assert_eq!(PrivateParallelLeaf(0), 0);
        assert_eq!(
            PrivateParallelRoot(identity),
            usize::from(mode() != "empty")
        );
        assert_eq!(PrivateParallelRoot(identity), 0);
        for lane in 0..5 {
            assert_eq!(PrivateParallelLeaf(lane), 0);
        }
    }
    for handle in HANDLES.lock().unwrap().drain(..) {
        assert_eq!(handle.join().unwrap(), 1);
    }
    assert!(
        SLOTS
            .iter()
            .all(|pointer| pointer.load(Ordering::Acquire).is_null())
    );
}

#[test]
fn gate_closes_admission_without_releasing_live_borrows() {
    let gate = Gate::new();
    assert!(gate.enter(0).is_none());
    assert!(gate.reserve());
    assert!(!gate.reserve());
    assert!(gate.publish());
    assert!(gate.enter(4).is_none());
    let ticket = gate.enter(2).unwrap();
    assert!(gate.enter(2).is_none());
    gate.close();
    assert!(!gate.quiescent());
    assert!(gate.enter(1).is_none());
    assert!(!gate.publish());
    ticket.succeeded();
    drop(ticket);
    assert!(gate.quiescent());
    assert!(!gate.all_succeeded());
}

#[test]
fn gate_close_races_workers_without_false_quiescence() {
    for _ in 0..128 {
        let gate = Gate::new();
        assert!(gate.reserve() && gate.publish());
        let barrier = Barrier::new(5);
        std::thread::scope(|scope| {
            for lane in 0..4 {
                let (gate, barrier) = (&gate, &barrier);
                scope.spawn(move || {
                    let ticket = gate.enter(lane).unwrap();
                    barrier.wait();
                    ticket.succeeded();
                    drop(ticket);
                    assert!(gate.enter(lane).is_none());
                });
            }
            barrier.wait();
            gate.close();
            while !gate.quiescent() {
                core::hint::spin_loop();
            }
            assert!(gate.all_succeeded());
        });
    }
}

#[test]
fn unsuccessful_or_unwound_worker_cannot_authorize_commit() {
    let gate = Gate::new();
    assert!(gate.reserve() && gate.publish());
    let result = std::panic::catch_unwind(|| {
        let _ticket = gate.enter(0).unwrap();
        panic!("synthetic unwind after claim");
    });
    assert!(result.is_err());
    gate.close();
    assert!(gate.quiescent() && !gate.all_succeeded());
}
