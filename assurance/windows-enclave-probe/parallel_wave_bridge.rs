//! Private multi-wave FFI adapter for fixed PUBLIC oracle inputs only.
//! Process tests do not establish enclave placement or native VBS execution.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use brynja_core::clear_owned_region;
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use brynja_hash_sha3::Fips202BitString as Bits;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use parallel_wave_gate::{Gate, Wave};
use parallel_waves::{Error, Plan, Slot, Waves};
mod parallel_wave_expected;

const TOTAL_BITS: usize = 32 * 9 * 8 + 3;
static CLAIMED: AtomicBool = AtomicBool::new(false);
static GATE: Gate = Gate::new();
static SLOTS: [AtomicPtr<Slot<'static>>; 4] = [const { AtomicPtr::new(core::ptr::null_mut()) }; 4];
static BITS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static OFFSET: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn PrivateWaveDispatch(generation: u32, lanes: usize) -> usize;
    fn PrivateWaveAbort() -> !;
    fn PrivateWaveRootRegion(pointer: usize, size: usize) -> usize;
}

fn authority() -> Option<Authority> {
    Authority::new(Kernel::X86Keccak).ok()
}

/// Scope guard additionally closes/joins on a Rust unwind in process tests.
/// Native panic=abort still makes no fatal-exit cleanup claim.
struct Publication<'gate> {
    wave: Wave<'gate>,
    retired: bool,
}
impl Publication<'_> {
    fn join(&self) {
        if self.retired {
            return;
        }
        self.wave.close();
        #[cfg(test)]
        parallel_wave_bridge_tests::closing(self.wave.generation());
        for _ in 0..0x100000000_u64 {
            if self.wave.quiescent() {
                for pointer in &SLOTS {
                    pointer.store(core::ptr::null_mut(), Ordering::Relaxed);
                }
                for bits in &BITS {
                    bits.store(0, Ordering::Relaxed);
                }
                OFFSET.store(0, Ordering::Relaxed);
                return;
            }
            core::hint::spin_loop();
        }
        // SAFETY: abort cannot free a still-borrowed root and continue execution.
        unsafe { PrivateWaveAbort() }
    }
}
impl Drop for Publication<'_> {
    fn drop(&mut self) {
        self.join();
        // Do not retire here: a failed/unwound operation seals the gate.
    }
}

fn contained<T: ?Sized>(value: &T) -> bool {
    // SAFETY: enclave-local metadata-only check; never dereferences the address.
    unsafe {
        PrivateWaveRootRegion(
            core::ptr::from_ref(value).cast::<()>() as usize,
            core::mem::size_of_val(value),
        ) == 1
    }
}

fn dispatch(
    offset: usize,
    plan: &Plan,
    slots: &mut [Slot<'_>],
) -> Result<Publication<'static>, Error> {
    let publication = Publication {
        wave: GATE.reserve(slots.len()).ok_or(Error::State)?,
        retired: false,
    };
    if !contained(plan) || !contained(slots) {
        return Err(Error::State);
    }
    OFFSET.store(offset, Ordering::Relaxed);
    for (index, slot) in slots.iter_mut().enumerate() {
        BITS[index].store(plan.leaf_bits(index)?, Ordering::Relaxed);
        // No 'static reference is manufactured: raw lifetime erased solely
        // during publication. Join completes before this scoped callback exits.
        SLOTS[index].store(
            core::ptr::from_mut(slot).cast::<Slot<'static>>(),
            Ordering::Relaxed,
        );
    }
    if !publication.wave.publish() {
        return Err(Error::State);
    }
    #[cfg(test)]
    parallel_wave_bridge_tests::before_dispatch(plan);
    // SAFETY: only public generation/shape crosses FFI; root slots stay alive
    // until our independent join, even if host returns early or claims success.
    let dispatched = unsafe { PrivateWaveDispatch(publication.wave.generation(), slots.len()) };
    publication.join();
    if dispatched != 1 || !publication.wave.all_succeeded() {
        return Err(Error::State);
    }
    Ok(publication)
}

/// # Safety
/// Baseline CPU and guarded root-window admission precede entry. This entire
/// call stays on the same admitted root frame/thread until all waves finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PrivateWaveRoot(identity: usize) -> usize {
    if !(1..=4).contains(&identity) || CLAIMED.swap(true, Ordering::AcqRel) {
        return 0;
    }
    root(identity).unwrap_or(0)
}

fn root(identity: usize) -> Option<usize> {
    let authority = authority()?;
    let mut root = Waves::new(
        &authority,
        identity as u64,
        32,
        TOTAL_BITS,
        Bits::new(&[], 0).ok()?,
        512,
    )
    .ok()?;
    if !contained(&authority) || !contained(&root) {
        return None;
    }
    // Three waves, ten leaves; the last leaf is three bits. Fixed public fixture.
    for _ in 0..3 {
        let mut publication = None;
        root.wave(|offset, plan, slots| {
            publication = Some(dispatch(offset, plan, slots)?);
            Ok(())
        })
        .ok()?;
        // Typed reduction and slot clearing have completed before retirement.
        // Disable further joins only after the protocol accepts retirement;
        // later guard Drop must not touch the next wave's pointer publication.
        let mut publication = publication?;
        publication.join();
        if !publication.wave.retire() {
            return None;
        }
        publication.retired = true;
    }
    root.finish().ok()?;
    let mut output = [0_u8; 64];
    let exported = root.declassify_to(&mut output).is_ok();
    let matched = exported && output == parallel_wave_expected::EXPECTED[identity - 1];
    let _ = clear_owned_region(&mut output);
    Some(usize::from(matched))
}

/// # Safety
/// Baseline CPU and independent worker-window admission precede entry. Request
/// context contains a generation, never a raw pointer. Rejection occurs before
/// any published slot/shape read, including on delayed previous-wave calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PrivateWaveLeaf(generation: u32, lane: usize) -> usize {
    let Some(ticket) = GATE.enter(generation, lane) else {
        return 0;
    };
    #[cfg(test)]
    parallel_wave_bridge_tests::after_claim(generation);
    let pointer = SLOTS[lane].load(Ordering::Relaxed);
    if pointer.is_null() {
        return 0;
    }
    let result = (|| {
        let authority = authority()?;
        let bits = BITS[lane].load(Ordering::Relaxed);
        if !(1..=256).contains(&bits) {
            return None;
        }
        let offset = OFFSET
            .load(Ordering::Relaxed)
            .checked_add(lane.checked_mul(32)?)?;
        let width = bits.div_ceil(8);
        let mut input = [0_u8; 32];
        for (index, byte) in input.iter_mut().enumerate() {
            *byte = ((offset + index) % 256) as u8;
        }
        let last = (bits - 1) % 8 + 1;
        input[width - 1] &= 0xff >> (8 - last);
        let result = match Bits::new(&input[..width], last as u8) {
            // SAFETY: ticket uniquely claims this generation's exclusive slot;
            // root cannot reduce, destroy or replace it until ticket release.
            Ok(input) => unsafe { (&mut *pointer).run(&authority, input).is_ok() },
            Err(_) => false,
        };
        let _ = clear_owned_region(&mut input);
        Some(result)
    })()
    .unwrap_or(false);
    if result {
        ticket.succeeded();
    }
    usize::from(result)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: fatal termination never returns with borrowed root storage freed.
    unsafe { PrivateWaveAbort() }
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod parallel_wave_bridge_tests;
