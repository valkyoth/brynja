//! Private single-thread enclave entry. No ordinary host execution is permitted.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use core::ptr::NonNull;
use sha2_batch::Owner;

static mut LIVE: Option<NonNull<Owner>> = None;
const _: () = assert!(core::mem::size_of::<Owner>() <= 4096);
const _: () = assert!(core::mem::align_of::<Owner>() <= 4096);
unsafe extern "C" {
    #[cfg(not(test))]
    fn PublicProbeAbort() -> !;
    fn PublicSha2BatchSource() -> usize;
    fn PublicSha2BatchInput(kind: usize, destination: *mut u8, source: usize, size: usize) -> i32;
    fn PublicSha2BatchOutput(source: *const u8, size: usize) -> i32;
    fn PublicSha2BatchObserve(header: usize, payload: usize, clear: usize) -> i32;
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: linked adapter aborts without claiming cleanup.
    unsafe { PublicProbeAbort() }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod sha2_batch_placement_tests;
struct Buffers {
    header: [u8; 128],
    payload: [u8; 1024],
}
impl Drop for Buffers {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(&mut self.header);
        let _ = brynja_core::clear_owned_region(&mut self.payload);
    }
}
fn within(address: usize, size: usize, low: usize, high: usize) -> bool {
    address >= low && address.checked_add(size).is_some_and(|end| end <= high)
}
fn receive(owner: &mut Owner, operation: usize, buffers: &mut Buffers) -> bool {
    // SAFETY: fixed synchronous OS transport into the admitted stack window.
    let source = unsafe { PublicSha2BatchSource() };
    if unsafe { PublicSha2BatchInput(0, buffers.header.as_mut_ptr(), source, 128) } != 0 {
        return false;
    }
    let Ok(header) = sha2_batch::sha2_batch_wire::Header::decode(operation, &buffers.header) else {
        return false;
    };
    let Some(input) = buffers.payload.get_mut(..header.length()) else {
        return false;
    };
    if !input.is_empty() {
        // SAFETY: bounded exclusive destination; OS validates source range.
        if unsafe { PublicSha2BatchInput(1, input.as_mut_ptr(), header.source(), input.len()) } != 0
        {
            return false;
        }
    }
    header
        .execute(owner, input, |bytes| {
            // SAFETY: only explicit EXPORT calls this fixed OS-copy seam.
            unsafe { PublicSha2BatchOutput(bytes.as_ptr(), bytes.len()) == 0 }
        })
        .is_ok()
}

/// # Safety
/// The serialized one-thread C entry owns one aligned live 4096-byte page for
/// the entire owner lifetime. It admits/resides the page and full stack before
/// entry and revokes access before either is released. No reference escapes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RetainedWork(
    operation: usize,
    page: *mut u8,
    low: usize,
    high: usize,
    _output: usize,
) -> usize {
    // SAFETY: linked C refuses reentry and initializes exactly one enclave thread.
    let live = unsafe { &mut *core::ptr::addr_of_mut!(LIVE) };
    if page.is_null() || page.addr() % 4096 != 0 || high.checked_sub(low) != Some(65536) {
        return 200;
    }
    if operation == 0 {
        if live.is_some() {
            return 201;
        }
        // SAFETY: newly admitted exclusive page; no live object yet. Constructor
        // contains only public initial metadata, never secret material.
        unsafe { page.cast::<Owner>().write(Owner::new()) };
        *live = NonNull::new(page.cast());
        return 1;
    }
    let Some(mut pointer) = *live else {
        return 202;
    };
    if pointer.as_ptr().cast::<u8>() != page {
        return 203;
    }
    if operation == 3 {
        // SAFETY: no operation borrow survives this synchronous entry; end the
        // typed lifetime before clearing inactive enum bytes and all padding.
        unsafe { pointer.as_ptr().drop_in_place() };
        *live = None;
        for offset in 0..4096 {
            // SAFETY: the entire admitted page remains writable and exclusive.
            unsafe { page.add(offset).write_volatile(0) };
        }
        return 4;
    }
    // SAFETY: unique page object, exact pointer identity verified above.
    let owner = unsafe { pointer.as_mut() };
    let mut buffers = Buffers {
        header: [0; 128],
        payload: [0; 1024],
    };
    let a = buffers.header.as_ptr().addr();
    let b = buffers.payload.as_ptr().addr();
    if !within(a, 128, low, high) || !within(b, 1024, low, high) {
        owner.quarantine();
        return 204;
    }
    let ok = receive(owner, operation, &mut buffers);
    if !ok {
        owner.quarantine();
    }
    let _ = brynja_core::clear_owned_region(&mut buffers.header);
    let _ = brynja_core::clear_owned_region(&mut buffers.payload);
    let cleared = buffers
        .header
        .iter()
        .chain(buffers.payload.iter())
        .all(|byte| {
            // SAFETY: initialized bytes in our live exclusive buffers.
            unsafe { core::ptr::read_volatile(byte) == 0 }
        });
    // SAFETY: report contains only public addresses and cleanup completion.
    if !cleared || unsafe { PublicSha2BatchObserve(a, b, usize::from(cleared)) } != 1 {
        owner.quarantine();
        return 205;
    }
    if ok { operation | (1_usize << 32) } else { 206 }
}
