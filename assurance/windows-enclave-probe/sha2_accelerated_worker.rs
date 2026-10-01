//! Private version-13 enclave entry, not a shipping host selection API.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use sha2_accelerated::sha2_accelerated_wire::Request;
use sha2_accelerated_resident::{Page, Resident};

// Only pointer/lifetime metadata lives here. Secret state and authority occupy
// the protected page; C permits exactly one serialized enclave thread.
static mut LIVE: Option<Resident<'static>> = None;
static mut LIVE_PAGE: usize = 0;
const _: () = assert!(core::mem::size_of::<Page>() == 4096);
const _: () = assert!(core::mem::align_of::<Page>() == 4096);

unsafe extern "C" {
    #[cfg(not(test))]
    fn PublicProbeAbort() -> !;
    fn PublicSha2Source() -> usize;
    fn PublicSha2Input(kind: usize, destination: *mut u8, source: usize, size: usize) -> i32;
    fn PublicSha2Output(source: *const u8, size: usize) -> i32;
    fn PublicSha2Observe(header: usize, payload: usize, clear: usize) -> i32;
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: linked baseline C aborts without claiming completed cleanup.
    unsafe { PublicProbeAbort() }
}
struct Buffers {
    header: [u8; 64],
    payload: [u8; 1024],
}
impl Buffers {
    fn clear(&mut self) {
        let _ = brynja_core::clear_owned_region(&mut self.header);
        let _ = brynja_core::clear_owned_region(&mut self.payload);
    }
}
impl Drop for Buffers {
    fn drop(&mut self) {
        self.clear();
    }
}
fn within(address: usize, size: usize, low: usize, high: usize) -> bool {
    address >= low && address.checked_add(size).is_some_and(|end| end <= high)
}
fn receive(owner: &mut Resident<'_>, operation: usize, buffers: &mut Buffers) -> bool {
    // SAFETY: fixed C accessor exposes only the currently registered opaque
    // host address; the OS copy primitive alone dereferences it.
    let source = unsafe { PublicSha2Source() };
    // SAFETY: exact exclusive buffer, already checked inside the protected stack.
    if unsafe { PublicSha2Input(0, buffers.header.as_mut_ptr(), source, 64) } != 0 {
        return false;
    }
    let Ok(request) = Request::decode(operation, &buffers.header) else {
        return false;
    };
    let Some(input) = buffers.payload.get_mut(..request.length) else {
        return false;
    };
    if request.length != 0 {
        // SAFETY: decoder bounds length/address; OS validates the untrusted source.
        if unsafe { PublicSha2Input(1, input.as_mut_ptr(), request.source, request.length) } != 0 {
            return false;
        }
    }
    owner
        .execute(operation, &buffers.header, input, |bytes| {
            // SAFETY: live enclave-owned digest; operation 15 explicitly authorizes
            // fixed OS copy-out. No generic host callback receives a secret slice.
            unsafe { PublicSha2Output(bytes.as_ptr(), bytes.len()) == 0 }
        })
        .is_ok()
}

/// # Safety
/// Called only by the linked serialized baseline C adapter, after complete CPU
/// bundle validation and protected page/stack admission. `page` is an aligned
/// exclusive 4096-byte allocation, disjoint from the 64-KiB worker window. C
/// keeps it alive and inaccessible to competing calls until operation 3 has
/// destroyed LIVE and returned status 4. No Rust entry is permitted otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RetainedWork(
    operation: usize,
    page: *mut u8,
    low: usize,
    high: usize,
    _output: usize,
) -> usize {
    // SAFETY: one enclave thread, synchronous C entry rejects recursive access.
    let live = unsafe { &mut *core::ptr::addr_of_mut!(LIVE) };
    // SAFETY: same serialization; this contains public allocation identity only.
    let identity = unsafe { &mut *core::ptr::addr_of_mut!(LIVE_PAGE) };
    let address = page.addr();
    if page.is_null()
        || address % 4096 != 0
        || high.checked_sub(low) != Some(65536)
        || !address
            .checked_add(4096)
            .is_some_and(|end| end <= low || address >= high)
    {
        if let Some(owner) = live.as_mut() {
            owner.quarantine();
        }
        return 200;
    }
    if operation == 0 {
        if let Some(owner) = live.as_mut() {
            owner.quarantine();
            return 201;
        }
        // SAFETY: fresh admitted page, no live references. Its sole typed borrow
        // is retained privately in LIVE. The C contract, not a host assertion,
        // preserves this allocation until the destructor completes below.
        unsafe {
            page.cast::<Page>().write(Page::empty());
        }
        // SAFETY: same allocation/lifetime guarantee; no reborrow of Page occurs
        // during the retained lifetime, and no page/owner reference escapes.
        let owner = match Resident::new(unsafe { &mut *page.cast::<Page>() }) {
            Ok(owner) => owner,
            Err(_) => return 207,
        };
        *live = Some(owner);
        *identity = address;
        return 1;
    }
    let Some(owner) = live.as_mut() else {
        return 202;
    };
    if *identity != address {
        owner.quarantine();
        return 203;
    }
    if operation == 3 {
        drop(live.take());
        *identity = 0;
        return 4;
    }
    let mut buffers = Buffers {
        header: [0; 64],
        payload: [0; 1024],
    };
    let header = buffers.header.as_ptr().addr();
    let payload = buffers.payload.as_ptr().addr();
    if !within(header, 64, low, high) || !within(payload, 1024, low, high) {
        owner.quarantine();
        return 204;
    }
    let ok = receive(owner, operation, &mut buffers);
    if !ok {
        owner.quarantine();
    }
    buffers.clear();
    let cleared = buffers
        .header
        .iter()
        .chain(buffers.payload.iter())
        .all(|byte| {
            // SAFETY: initialized live exclusive buffers, within the admitted window.
            unsafe { core::ptr::read_volatile(byte) == 0 }
        });
    // SAFETY: public addresses/cleanup receipt only; no secret data transferred.
    if !cleared || unsafe { PublicSha2Observe(header, payload, usize::from(cleared)) } != 1 {
        owner.quarantine();
        return 205;
    }
    if ok { operation | (1_usize << 32) } else { 206 }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod sha2_accelerated_worker_tests;
