//! Private single-thread enclave entry. No ordinary host execution is permitted.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use core::ptr::NonNull;
use sha3_stream::Owner;

static mut LIVE: Option<NonNull<Owner>> = None;
const _: () = assert!(core::mem::size_of::<Owner>() <= 4096);
const _: () = assert!(core::mem::align_of::<Owner>() <= 4096);
unsafe extern "C" {
    #[cfg(not(test))]
    fn PublicProbeAbort() -> !;
    fn PublicSha3Source() -> usize;
    fn PublicSha3Input(kind: usize, destination: *mut u8, source: usize, size: usize) -> i32;
    fn PublicSha3Output(source: *const u8, size: usize) -> i32;
    fn PublicSha3Observe(header: usize, payload: usize, clear: usize) -> i32;
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
mod sha3_stream_placement_tests;
struct Buffers {
    header: [u8; 96],
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
fn word(bytes: &[u8], index: usize) -> Option<u64> {
    let start = index.checked_mul(8)?;
    Some(u64::from_le_bytes(
        bytes.get(start..start.checked_add(8)?)?.try_into().ok()?,
    ))
}
fn receive(owner: &mut Owner, operation: usize, buffers: &mut Buffers) -> bool {
    // SAFETY: fixed synchronous OS transport into the admitted stack window.
    let source = unsafe { PublicSha3Source() };
    if unsafe { PublicSha3Input(0, buffers.header.as_mut_ptr(), source, 96) } != 0 {
        return false;
    }
    let mut fields = [0_u64; 12];
    for (index, field) in fields.iter_mut().enumerate() {
        let Some(value) = word(&buffers.header, index) else {
            return false;
        };
        *field = value;
    }
    let [
        version,
        sequence,
        algorithm,
        length,
        last,
        source,
        width,
        terminal,
        nlow,
        nhigh,
        slow,
        shigh,
    ] = fields;
    if version != 7 || sequence == 0 || length > 1024 || width > 1024 || last > 8 || terminal > 1 {
        return false;
    }
    let (Ok(length), Ok(source), Ok(width), Ok(last)) = (
        usize::try_from(length),
        usize::try_from(source),
        usize::try_from(width),
        u8::try_from(last),
    ) else {
        return false;
    };
    if (source == 0) != (length == 0) || source.checked_add(length).is_none() {
        return false;
    }
    let payload = matches!(operation, 22 | 23 | 29 | 30);
    if !payload && length != 0 {
        return false;
    }
    if !matches!(operation, 21 | 24 | 25 | 28) && algorithm != 0 {
        return false;
    }
    if !matches!(operation, 25 | 27) && width != 0 {
        return false;
    }
    if operation != 27 && terminal != 0 {
        return false;
    }
    if operation != 28 && (nlow != 0 || nhigh != 0 || slow != 0 || shigh != 0) {
        return false;
    }
    if !payload && !matches!(operation, 25 | 27) && last != 0 {
        return false;
    }
    if payload && ((length == 0 && last != 0) || (length != 0 && last == 0)) {
        return false;
    }
    if operation == 22 && last != if length == 0 { 0 } else { 8 } {
        return false;
    }
    let Some(input) = buffers.payload.get_mut(..length) else {
        return false;
    };
    if length != 0 {
        // SAFETY: the exclusive destination is bounded above; OS validates source.
        if unsafe { PublicSha3Input(1, input.as_mut_ptr(), source, length) } != 0 {
            return false;
        }
    }
    let Ok(empty) = brynja_hash_sha3::Fips202BitString::new(&[], 0) else {
        return false;
    };
    match operation {
        21 => owner.begin(sequence, algorithm, empty, empty),
        22 => owner.update(sequence, input),
        23 => owner.finish(sequence, input, last),
        24 => owner.rehash(sequence, algorithm, empty, empty),
        25 => owner.export_public(sequence, algorithm, width, last, |bytes| {
            // SAFETY: explicit public output operation and fixed OS copy only.
            unsafe { PublicSha3Output(bytes.as_ptr(), bytes.len()) == 0 }
        }),
        26 => owner.cancel(sequence),
        27 => owner.squeeze(sequence, width, last, terminal == 1),
        28 => owner.setup(
            sequence,
            algorithm,
            u128::from(nlow) | (u128::from(nhigh) << 64),
            u128::from(slow) | (u128::from(shigh) << 64),
        ),
        29 | 30 => owner.setup_chunk(sequence, operation == 29, input, last),
        31 => owner.finish_setup(sequence),
        _ => return false,
    }
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
        header: [0; 96],
        payload: [0; 1024],
    };
    let a = buffers.header.as_ptr().addr();
    let b = buffers.payload.as_ptr().addr();
    if !within(a, 96, low, high) || !within(b, 1024, low, high) {
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
    if !cleared || unsafe { PublicSha3Observe(a, b, usize::from(cleared)) } != 1 {
        owner.quarantine();
        return 205;
    }
    if ok { operation | (1_usize << 32) } else { 206 }
}
