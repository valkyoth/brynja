//! Private single-operation enclave integration using PUBLIC synthetic inputs.
//! Not a supported API or whole-image register/spill qualification.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use brynja_core::clear_owned_region;
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use brynja_hash_sha3::Fips202BitString as Bits;
use core::sync::atomic::{AtomicPtr, Ordering};
use parallel_concurrent::{Batch, Plan, Slot};
mod parallel_concurrent_expected;
mod parallel_concurrent_gate;
use parallel_concurrent_gate::Gate;

static GATE: Gate = Gate::new();
// Lifetime erased only during one root's scoped publication. The root closes
// admission and acquires every worker's final release before touching its Batch.
static SLOTS: [AtomicPtr<Slot<'static>>; 4] = [const { AtomicPtr::new(core::ptr::null_mut()) }; 4];

unsafe extern "C" {
    fn PrivateParallelDispatch() -> usize;
    fn PrivateParallelAbort() -> !;
    fn PrivateParallelRootRegion(pointer: usize, size: usize) -> usize;
}

fn authority() -> Option<Authority> {
    Authority::new(Kernel::X86Keccak).ok()
}

fn join() {
    GATE.close();
    // A host callback may lie about joining. Never unwind/drop the root while
    // any enclave worker can access it. Availability failure is process-fatal.
    for _ in 0..0x100000000_u64 {
        if GATE.quiescent() {
            for pointer in &SLOTS {
                pointer.store(core::ptr::null_mut(), Ordering::Relaxed);
            }
            return;
        }
        core::hint::spin_loop();
    }
    // SAFETY: Baseline enclave C abort terminates; it must never return.
    unsafe { PrivateParallelAbort() }
}

/// # Safety
/// Only baseline-CPU-checked C may call this, from an admitted guarded root
/// window. The root window remains live and resident across dispatch and join.
/// Exactly one operation per image. No authority crosses an OS thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PrivateParallelRoot(identity: usize) -> usize {
    if !(1..=4).contains(&identity) || !GATE.reserve() {
        return 0;
    }
    root(identity).unwrap_or(0)
}
fn root(identity: usize) -> Option<usize> {
    let authority = authority()?;
    let plan = Plan::new(identity as u64, 32, 1024, 0, 512).ok()?;
    let mut batch = Batch::new(&plan, &authority).ok()?;
    // SAFETY: only address/size metadata is checked inside the enclave; the C
    // check never dereferences it and requires containment in the live root.
    if unsafe {
        PrivateParallelRootRegion(
            core::ptr::from_ref(&plan) as usize,
            core::mem::size_of_val(&plan),
        ) & PrivateParallelRootRegion(
            core::ptr::from_ref(&authority) as usize,
            core::mem::size_of_val(&authority),
        ) & PrivateParallelRootRegion(
            core::ptr::from_ref(&batch) as usize,
            core::mem::size_of_val(&batch),
        )
    } != 1
    {
        return None;
    }
    let workers = batch.workers().ok()?;
    for (pointer, slot) in SLOTS.iter().zip(workers.iter_mut()) {
        // Raw-pointer lifetime cast does not create a 'static reference.
        pointer.store(
            core::ptr::from_mut(slot).cast::<Slot<'static>>(),
            Ordering::Relaxed,
        );
    }
    if !GATE.publish() {
        join();
        return None;
    }
    // SAFETY: Only public dispatch metadata crosses C. Borrowed slots are kept
    // alive here until join has closed admission and observed all final releases.
    let dispatched = unsafe { PrivateParallelDispatch() };
    join();
    if dispatched != 1 || !GATE.all_succeeded() {
        return None;
    }
    batch.finish(Bits::new(&[], 0).ok()?).ok()?;
    let mut output = [0_u8; 64];
    let exported = batch.declassify_to(&mut output).is_ok();
    let matched = exported && output == parallel_concurrent_expected::EXPECTED[identity - 1];
    let _ = clear_owned_region(&mut output);
    Some(usize::from(matched))
}

/// # Safety
/// Baseline CPU check and independent worker-window admission precede this
/// call. The root's publication protocol—not host input—supplies the pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PrivateParallelLeaf(lane: usize) -> usize {
    let Some(ticket) = GATE.enter(lane) else {
        return 0;
    };
    #[cfg(test)]
    parallel_concurrent_bridge_tests::after_claim();
    let pointer = SLOTS[lane].load(Ordering::Relaxed);
    if pointer.is_null() {
        return 0;
    }
    let result = {
        let Some(authority) = authority() else {
            return 0;
        };
        // All input bytes in this experiment are public fixed oracle fixtures.
        let mut input = [0_u8; 32];
        for (index, byte) in input.iter_mut().enumerate() {
            *byte = (lane * 32 + index) as u8;
        }
        let result = match Bits::new(&input, 8) {
            // SAFETY: successful ticket uniquely claims this disjoint slot once.
            // Root waits for Ticket::drop before accessing or destroying the slots.
            Ok(bits) => unsafe { (&mut *pointer).run(&authority, bits).is_ok() },
            Err(_) => false,
        };
        let _ = clear_owned_region(&mut input);
        result
    };
    if result {
        ticket.succeeded();
    }
    // Ticket is dropped only after the last slot access and local owner cleanup.
    usize::from(result)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: fatal termination cannot release a still-borrowed root frame.
    unsafe { PrivateParallelAbort() }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod parallel_concurrent_bridge_tests;
