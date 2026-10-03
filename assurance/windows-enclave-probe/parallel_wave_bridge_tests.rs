use super::*;
use core::sync::atomic::AtomicU32;
static ENTERED: AtomicUsize = AtomicUsize::new(0);
static CLOSING: AtomicU32 = AtomicU32::new(0);
static DISPATCHES: AtomicUsize = AtomicUsize::new(0);
static HANDLES: std::sync::Mutex<std::vec::Vec<std::thread::JoinHandle<usize>>> =
    std::sync::Mutex::new(std::vec::Vec::new());

fn mode() -> std::string::String {
    std::env::var("BRYNJA_WAVE_MODE").unwrap()
}
fn selected(generation: u32) -> bool {
    generation
        == std::env::var("BRYNJA_WAVE_FAIL_AT")
            .unwrap()
            .parse::<u32>()
            .unwrap()
}
pub fn closing(generation: u32) {
    CLOSING.store(generation, Ordering::Release);
}
pub fn before_dispatch(plan: &Plan) {
    let generation = u32::try_from(DISPATCHES.load(Ordering::Acquire) + 1).unwrap();
    if selected(generation) {
        if mode() == "unwind" {
            panic!("synthetic internal pre-dispatch unwind");
        }
        if mode() == "cancel" {
            plan.cancel();
        }
    }
}
pub fn after_claim(generation: u32) {
    if mode() == "early" && selected(generation) {
        ENTERED.fetch_add(1, Ordering::Release);
        while CLOSING.load(Ordering::Acquire) < generation {
            std::thread::yield_now();
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn PrivateWaveDispatch(generation: u32, lanes: usize) -> usize {
    assert_eq!(
        DISPATCHES.fetch_add(1, Ordering::AcqRel) + 1,
        generation as usize
    );
    assert_eq!(lanes, if generation == 3 { 2 } else { 4 });
    // Invalid contexts must reject before reading current-generation pointers.
    for stale in [0, generation - 1, generation + 1, u32::MAX] {
        for lane in 0..4 {
            // SAFETY: deliberately malformed public metadata; admission must reject.
            assert_eq!(unsafe { PrivateWaveLeaf(stale, lane) }, 0);
        }
    }
    for lane in lanes..=4 {
        // SAFETY: inactive lane, no borrowed storage is authorized.
        assert_eq!(unsafe { PrivateWaveLeaf(generation, lane) }, 0);
    }
    if mode() == "empty" && selected(generation) {
        return 1;
    }
    if mode() == "early" && selected(generation) {
        ENTERED.store(0, Ordering::Release);
        for lane in 0..lanes {
            HANDLES.lock().unwrap().push(std::thread::spawn(move || {
                // SAFETY: root independently joins even though this host won't.
                unsafe { PrivateWaveLeaf(generation, lane) }
            }));
        }
        while ENTERED.load(Ordering::Acquire) != lanes {
            std::thread::yield_now();
        }
        return 1;
    }
    let count = if mode() == "missing" && selected(generation) {
        lanes - 1
    } else {
        lanes
    };
    std::thread::scope(|scope| {
        let handles: std::vec::Vec<_> = (0..count)
            .rev()
            .map(|lane| {
                scope.spawn(move || {
                    // SAFETY: matching context; original root remains live and joined.
                    let result = unsafe { PrivateWaveLeaf(generation, lane) };
                    // Permanent per-wave claims reject replay even after completion.
                    assert_eq!(unsafe { PrivateWaveLeaf(generation, lane) }, 0);
                    result
                })
            })
            .collect();
        for handle in handles {
            assert_eq!(
                handle.join().unwrap(),
                usize::from(!(mode() == "cancel" && selected(generation)))
            );
        }
    });
    1
}
#[unsafe(no_mangle)]
extern "C" fn PrivateWaveAbort() -> ! {
    std::process::abort()
}
#[unsafe(no_mangle)]
extern "C" fn PrivateWaveRootRegion(_: usize, _: usize) -> usize {
    1
}

#[test]
fn scoped_generation_bridge_checks_oracle_and_terminal_failures() {
    let identity = std::env::var("BRYNJA_WAVE_ID").unwrap().parse().unwrap();
    // No root yet: no fixture or slot can be reached with a guessed request.
    assert_eq!(unsafe { PrivateWaveLeaf(1, 0) }, 0);
    let success = matches!(mode().as_str(), "normal" | "early");
    if mode() == "unwind" {
        // Do not unwind across extern C: exercise the private Rust call instead.
        assert!(std::panic::catch_unwind(|| root(identity)).is_err());
    } else {
        // SAFETY: native AVX2 process; no enclave-residency claim in these tests.
        assert_eq!(unsafe { PrivateWaveRoot(identity) }, usize::from(success));
        assert_eq!(unsafe { PrivateWaveRoot(identity) }, 0);
    }
    for handle in HANDLES.lock().unwrap().drain(..) {
        assert_eq!(handle.join().unwrap(), 1);
    }
    assert_eq!(
        DISPATCHES.load(Ordering::Acquire),
        if success {
            3
        } else {
            std::env::var("BRYNJA_WAVE_FAIL_AT")
                .unwrap()
                .parse::<usize>()
                .unwrap()
                - usize::from(mode() == "unwind")
        }
    );
    assert!(SLOTS.iter().all(|p| p.load(Ordering::Acquire).is_null()));
    assert!(BITS.iter().all(|p| p.load(Ordering::Acquire) == 0));
    assert_eq!(OFFSET.load(Ordering::Acquire), 0);
    for generation in 0..=4 {
        for lane in 0..=4 {
            assert_eq!(unsafe { PrivateWaveLeaf(generation, lane) }, 0);
        }
    }
    if !success {
        assert!(GATE.reserve(1).is_none());
    }
}
