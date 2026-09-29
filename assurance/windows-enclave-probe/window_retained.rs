//! Fixed PUBLIC-vector native fixture. Not a shipping secret API.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use brynja_hash_sha2::hardened_in_place::Sha256Workspace;
use persistent_result::{Error, PUBLIC_OUTPUT};
use retained_placement::{PAGE, Placed};

// The linked C image has exactly one enclave thread, refuses reentry and only
// enters here from its admitted guarded worker. No reference crosses the ABI.
static mut LIVE: Option<Placed<'static>> = None;
static mut TOKEN: [u64; 4] = [0; 4];
static mut EPOCH: u64 = 0;
const _: () = assert!(core::mem::size_of::<Sha256Workspace>() == 1170);
const _: () = assert!(core::mem::align_of::<Sha256Workspace>() == 1);

unsafe extern "C" {
    fn PublicRetainedCopy(destination: usize, source: *const u8, length: usize) -> i32;
    #[cfg(not(test))]
    fn PublicProbeAbort() -> !;
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: nonreturning linked research adapter; no abort cleanup claim.
    unsafe { PublicProbeAbort() }
}

fn code(result: Result<(), Error>, success: usize) -> usize {
    match result {
        Ok(()) => success,
        Err(Error::Identity) => 100,
        Err(Error::Busy) => 101,
        Err(Error::Spent) => 102,
        Err(Error::Rejected) => 103,
        Err(Error::Fill) => 104,
        Err(Error::Copy) => 105,
        Err(Error::Exhausted) => 106,
        Err(Error::Quarantined) => 107,
        Err(Error::Closed) => 108,
    }
}
fn within(address: usize, size: usize, low: usize, high: usize) -> bool {
    address >= low && address.checked_add(size).is_some_and(|end| end <= high)
}
fn fill(case: usize, input: &mut [u8; 1024]) -> Option<usize> {
    const TEXT: [&[u8]; 4] = [b"", b"abc",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"];
    const LENGTHS: [usize; 20] = [
        0, 3, 56, 112, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 511, 512, 1024,
    ];
    let length = *LENGTHS.get(case)?;
    for (index, byte) in input.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(17).wrapping_add(case as u8);
    }
    if let Some(text) = TEXT.get(case) {
        input[..length].copy_from_slice(text);
    }
    Some(length)
}
#[inline(never)]
fn hash(owner: &mut Placed<'_>, case: usize, low: usize, high: usize) -> (usize, Option<[u64; 4]>) {
    let mut workspace = Sha256Workspace::new();
    let mut input = [0_u8; 1024];
    let mut staging = [0_u8; 32];
    if high.checked_sub(low) != Some(65536)
        || !within(core::ptr::from_ref(&workspace).addr(), 1170, low, high)
        || !within(input.as_ptr().addr(), input.len(), low, high)
        || !within(staging.as_ptr().addr(), staging.len(), low, high)
    {
        return (190, None);
    }
    compute(owner, case, &mut workspace, &mut input, &mut staging)
}

fn compute(
    owner: &mut Placed<'_>,
    case: usize,
    workspace: &mut Sha256Workspace,
    input: &mut [u8; 1024],
    staging: &mut [u8; 32],
) -> (usize, Option<[u64; 4]>) {
    // A fresh workspace contains the public IV. Clear it BEFORE the attempted
    // operation so early Busy/Quarantined rejection has a meaningful zero check.
    // No post-operation scope/wipe may conceal a failed operation's residue.
    workspace.with(|state| state.cancel());
    let Some(length) = fill(case, input) else {
        return (192, None);
    };
    let result = owner.hash(workspace, staging, &input[..length]);
    let _ = brynja_core::clear_owned_region(input);
    // SAFETY: builder checks the exact initialized eight-byte-array layout and
    // ZST marker; static size/alignment exclude padding. Operation borrow ended.
    let bytes =
        unsafe { core::slice::from_raw_parts(core::ptr::from_ref(&*workspace).cast::<u8>(), 1170) };
    if bytes
        .iter()
        .chain(input.iter())
        .chain(staging.iter())
        .any(|byte| {
            // SAFETY: initialized live byte, no concurrent writer.
            unsafe { core::ptr::read_volatile(byte) != 0 }
        })
    {
        return (191, None);
    }
    match result {
        Ok(token) => (2 | (1_usize << 32), Some(token)),
        Err(error) => (code(Err(error), 0) | (1_usize << 32), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;
    #[repr(align(4096))]
    struct Page([MaybeUninit<u8>; PAGE]);
    #[unsafe(no_mangle)]
    extern "C" fn PublicRetainedCopy(_: usize, _: *const u8, _: usize) -> i32 {
        -1
    }

    #[test]
    fn fresh_workspace_rejections_are_zero_without_masking_post_operation_cleanup() {
        let mut page = Page([MaybeUninit::new(0); PAGE]);
        let mut owner = Placed::new(&mut page.0, [1, 2]).unwrap();
        let mut input = [0; 1024];
        let mut staging = [0; 32];
        for expected in [2, 101, 107] {
            let mut workspace = Sha256Workspace::new();
            let (status, _) = compute(&mut owner, 1, &mut workspace, &mut input, &mut staging);
            assert_eq!(status, expected | (1_usize << 32));
            assert_eq!(input, [0; 1024]);
            assert_eq!(staging, [0; 32]);
            if expected == 101 {
                owner.quarantine();
            }
        }
    }
}

/// # Safety
/// Private linked C caller supplies the exclusive resident page across calls,
/// never touches it while LIVE exists, and releases it only after successful
/// operation 3 and independent zero readback. Exactly one admitted worker may
/// enter; no Rust reference may survive the call other than LIVE's page borrow.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RetainedWork(
    operation: usize,
    page: *mut u8,
    low: usize,
    high: usize,
    output: usize,
) -> usize {
    // SAFETY: serialized, nonreentrant one-thread fixture described above.
    let live = unsafe { &mut *core::ptr::addr_of_mut!(LIVE) };
    let op = operation & 255;
    if op == 0 {
        if live.is_some() {
            return 101;
        }
        // SAFETY: same exclusive serialized entry; public monotonic metadata.
        let epoch = unsafe { &mut *core::ptr::addr_of_mut!(EPOCH) };
        let Some(next) = epoch.checked_add(1) else {
            return 106;
        };
        if page.is_null() || page.addr() % PAGE != 0 {
            return 193;
        }
        // SAFETY: C owns the entire admitted page until operation 3. Fresh full
        // slice authority is established only at construction, never per use.
        let storage = unsafe { core::slice::from_raw_parts_mut(page.cast(), PAGE) };
        let Ok(owner) = Placed::new(storage, [0x52455441494e, next]) else {
            return 193;
        };
        *epoch = next;
        *live = Some(owner);
        return 1;
    }
    if op == 3 {
        let Some(owner) = live.take() else {
            return 102;
        };
        if cfg!(probe_retained_forget) {
            core::mem::forget(owner);
        } else {
            drop(owner);
        }
        // SAFETY: public token metadata, exclusively owned by this entry.
        unsafe { TOKEN = [0; 4] };
        return 4;
    }
    let Some(owner) = live.as_mut() else {
        return 102;
    };
    // SAFETY: public metadata protected by the same one-thread entry contract.
    let token = unsafe { &mut *core::ptr::addr_of_mut!(TOKEN) };
    match op {
        1 => {
            let (status, next) = hash(owner, operation >> 8, low, high);
            if let Some(next) = next {
                *token = next;
                if cfg!(probe_retained_discard) {
                    let _ = owner.cancel(next);
                }
            }
            status
        }
        2 | 5 | 6 => {
            if cfg!(probe_retained_no_export) {
                return 3;
            }
            let mut supplied = *token;
            if op == 5 {
                supplied[2] ^= 1;
            }
            code(
                owner.export_public(supplied, PUBLIC_OUTPUT, |bytes| {
                    // SAFETY: initialized enclave slice lives through the fixed OS
                    // copy call; opaque host address is never dereferenced by Rust.
                    unsafe {
                        PublicRetainedCopy(
                            if op == 6 { 0 } else { output },
                            bytes.as_ptr(),
                            bytes.len(),
                        ) == 0
                    }
                }),
                3,
            )
        }
        4 => code(owner.cancel(*token), 5),
        7 => {
            owner.quarantine();
            6
        }
        _ => 194,
    }
}
