//! Direct-copy input worker experiment; public vectors only, not a shipping secret API.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use brynja_core::clear_owned_region;
use brynja_hash_sha2::hardened_in_place::Sha256Workspace;

mod wire_protocol;
use enclave_borrowed::{CAPACITY, HEADER as SIZE, Snapshot};
use enclave_result::Issuer;
use wire_protocol::COMMAND;
const _: () = assert!(core::mem::size_of::<Snapshot>() == CAPACITY);
const _: () = assert!(core::mem::align_of::<Snapshot>() == 1);
const OWNER: usize = 1170;
const _: () = assert!(core::mem::size_of::<Sha256Workspace>() == OWNER);
const _: () = assert!(core::mem::align_of::<Sha256Workspace>() == 1);

#[repr(C)]
pub struct Report {
    status: usize,
    snapshot: usize,
    workspace: usize,
    output: usize,
    absorbed: usize,
    cleared: usize,
    replay: usize,
    owner_size: usize,
}

unsafe extern "C" {
    fn PublicCopyIn(destination: *mut u8, source: usize, size: usize) -> i32;
    fn PublicCopyOut(destination: usize, source: *const u8, size: usize) -> i32;
    fn PublicWireNotify(step: usize) -> i32;
    fn PublicWireIdentity(output: *mut u64) -> i32;
    fn PublicBorrowedCopied() -> i32;
    #[cfg(not(test))]
    fn PublicProbeAbort() -> !;
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: experiment-only fatal C adapter; no recovery or cleanup claim.
    unsafe { PublicProbeAbort() }
}

trait Transport {
    fn identity(&mut self) -> Option<[u64; 4]>;
    fn read(&mut self, address: usize, destination: &mut [u8]) -> bool;
    fn write(&mut self, address: usize, source: &[u8]) -> bool;
    fn notify(&mut self, step: usize) -> bool;
}
struct Native;
impl Transport for Native {
    fn identity(&mut self) -> Option<[u64; 4]> {
        let mut token = [0; 4];
        // SAFETY: exclusive initialized four-word destination; trusted linked C
        // copies public instance/scope metadata only while the worker is active.
        if unsafe { PublicWireIdentity(token.as_mut_ptr()) } == 1 {
            Some(token)
        } else {
            None
        }
    }
    fn read(&mut self, address: usize, destination: &mut [u8]) -> bool {
        // SAFETY: full initialized, exclusive enclave destination. The opaque
        // host address is validated/dereferenced only by the platform copy API.
        unsafe { PublicCopyIn(destination.as_mut_ptr(), address, destination.len()) == 0 }
    }
    fn write(&mut self, address: usize, source: &[u8]) -> bool {
        // SAFETY: live shared enclave source; opaque host address goes only to
        // the platform API. Offers contain public metadata; digests are public.
        unsafe { PublicCopyOut(address, source.as_ptr(), source.len()) == 0 }
    }
    fn notify(&mut self, step: usize) -> bool {
        // SAFETY: two fixed research events only; no Rust object escapes.
        unsafe { PublicWireNotify(step) == 1 }
    }
}

trait Input {
    fn copy(&mut self, address: u64, destination: &mut [u8]) -> bool;
}
struct NativeInput;
impl Input for NativeInput {
    fn copy(&mut self, address: u64, destination: &mut [u8]) -> bool {
        let Ok(address) = usize::try_from(address) else {
            return false;
        };
        // SAFETY: destination is an initialized, exclusively borrowed region in
        // the preadmitted worker window. The OS alone dereferences host memory.
        let copied =
            unsafe { PublicCopyIn(destination.as_mut_ptr(), address, destination.len()) == 0 };
        // SAFETY: public diagnostic event after the copy, never an input reference.
        copied && unsafe { PublicBorrowedCopied() == 1 }
    }
}
fn snapshot_zero(snapshot: &Snapshot) -> bool {
    // SAFETY: repr(C) is one initialized byte array plus a zero-sized marker;
    // size/alignment assertions exclude padding. No active mutable scope exists.
    zero(unsafe { core::slice::from_raw_parts(core::ptr::from_ref(snapshot).cast(), CAPACITY) })
}

fn zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0, |value, byte| {
        // SAFETY: initialized, live shared byte without concurrent mutation.
        value | unsafe { core::ptr::read_volatile(byte) }
    }) == 0
}
fn workspace_zero(workspace: &Sha256Workspace) -> bool {
    // SAFETY: builder checks the exact eight initialized byte-array fields and
    // zero-sized marker; compile-time size/alignment exclude padding. Scope has
    // ended, no mutable handle is alive, and the workspace has not been dropped.
    zero(unsafe { core::slice::from_raw_parts(core::ptr::from_ref(workspace).cast(), OWNER) })
}
#[repr(C)]
struct Buffers {
    snapshot: [u8; SIZE],
    payload: Snapshot,
    command: [u8; COMMAND],
    output: [u8; 32],
}
impl Buffers {
    fn clear(&mut self) {
        if cfg!(probe_skip_wire_clear) {
            return;
        }
        let _ = clear_owned_region(&mut self.snapshot);
        let _ = clear_owned_region(&mut self.command);
        let _ = clear_owned_region(&mut self.output);
    }
}
impl Drop for Buffers {
    fn drop(&mut self) {
        self.clear();
    }
}

fn exchange(
    handle: &mut enclave_result::ResultHandle<'_>,
    token: [u64; 4],
    address: usize,
    command: &mut [u8; COMMAND],
    io: &mut impl Transport,
) -> (usize, usize) {
    let mut outcomes = [0_usize; 2];
    for step in 0..2 {
        wire_protocol::offer(token, if step == 0 { 0 } else { outcomes[0] }, command);
        let failure = if !io.write(address, command) {
            18
        } else if !io.notify(step) {
            13
        } else if !io.read(address, command) {
            11
        } else {
            0
        };
        if failure != 0 {
            let _ = handle.cancel(handle.token());
            outcomes[step] = failure;
            break;
        }
        outcomes[step] = wire_protocol::consume(handle, token, command, |destination, data| {
            io.write(destination, data)
        });
    }
    (outcomes[0], outcomes[1])
}

fn operation(
    workspace: &mut Sha256Workspace,
    buffers: &mut Buffers,
    source: usize,
    io: &mut impl Transport,
    input: &mut impl Input,
) -> (usize, usize, usize) {
    workspace.with(|state| state.cancel());
    let Some(token) = io.identity() else {
        return (15, 0, 0);
    };
    if token[0] | token[1] == 0 || token[2] == 0 || token[3] != 1 {
        return (15, 0, 0);
    }
    if !io.read(source, &mut buffers.snapshot) {
        return (11, 0, 0);
    }
    let Ok(mut issuer) = Issuer::new(token[2]) else {
        return (15, 0, 0);
    };
    let result = buffers.payload.with(
        &buffers.snapshot,
        |address, destination| input.copy(address, destination),
        |bytes, address| {
            let length = bytes.len();
            let result = issuer.sha256(workspace, &mut buffers.output, bytes, |handle| {
                exchange(handle, token, address as usize, &mut buffers.command, io)
            });
            (length, result)
        },
    );
    if !workspace_zero(workspace) || !zero(&buffers.output) || !snapshot_zero(&buffers.payload) {
        return (19, 0, 0);
    }
    match result {
        Ok((length, Ok((first, second)))) => (first, length, second),
        Ok((length, Err(_))) => (19, length, 0),
        Err(enclave_borrowed::Error::Copy) => (11, 0, 0),
        Err(_) => (10, 0, 0),
    }
}

fn within(address: usize, size: usize, low: usize, high: usize) -> bool {
    address >= low && address.checked_add(size).is_some_and(|end| end <= high)
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn PublicWireWork(source: usize, low: usize, high: usize) -> Report {
    let mut report = Report {
        status: 19,
        snapshot: 0,
        workspace: 0,
        output: 0,
        absorbed: 0,
        cleared: 0,
        replay: 0,
        owner_size: OWNER,
    };
    if high.checked_sub(low) != Some(65536) {
        return report;
    }
    let mut workspace = Sha256Workspace::new();
    let mut buffers = Buffers {
        snapshot: [0; SIZE],
        payload: Snapshot::new(),
        command: [0; COMMAND],
        output: [0; 32],
    };
    report.snapshot = buffers.snapshot.as_ptr() as usize;
    report.workspace = core::ptr::from_ref(&workspace) as usize;
    report.output = buffers.output.as_ptr() as usize;
    if !within(report.snapshot, SIZE + CAPACITY + COMMAND, low, high)
        || !within(report.workspace, OWNER, low, high)
        || !within(report.output, 32, low, high)
    {
        return report;
    }
    let (status, absorbed, replay) = operation(
        &mut workspace,
        &mut buffers,
        source,
        &mut Native,
        &mut NativeInput,
    );
    buffers.clear();
    report.cleared = usize::from(
        zero(&buffers.snapshot)
            && snapshot_zero(&buffers.payload)
            && zero(&buffers.command)
            && zero(&buffers.output)
            && workspace_zero(&workspace),
    );
    report.status = if report.cleared == 1 { status } else { 19 };
    report.absorbed = absorbed;
    report.replay = replay;
    report
}

#[cfg(test)]
#[path = "window_borrowed_tests.rs"]
mod tests;
