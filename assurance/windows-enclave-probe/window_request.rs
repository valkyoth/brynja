//! Bounded public-data request prototype, not a protected host-secret channel.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use brynja_core::clear_owned_region;
use brynja_hash_sha2::hardened_in_place::Sha256Workspace;

const SIZE: usize = 1072;
const OWNER: usize = 1170;
const PUBLIC: u64 = 0x5055_424c_4943;
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
    exported: usize,
    owner_size: usize,
}

unsafe extern "C" {
    fn PublicCopyIn(destination: *mut u8, source: usize, size: usize) -> i32;
    fn PublicCopyOut(destination: usize, source: *const u8, size: usize) -> i32;
    fn PublicSnapshotReady() -> i32;
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
    fn read(&mut self, destination: &mut [u8; SIZE]) -> bool;
    fn copied(&mut self) -> bool;
    fn write(&mut self, destination: usize, source: &[u8; 32]) -> bool;
}
struct Native(usize);
impl Transport for Native {
    fn read(&mut self, destination: &mut [u8; SIZE]) -> bool {
        // SAFETY: destination exclusively borrows the full initialized allocation.
        // C passes the opaque host address ONLY to EnclaveCopyIntoEnclave; no
        // Rust reference is constructed for untrusted memory. Only S_OK passes.
        unsafe { PublicCopyIn(destination.as_mut_ptr(), self.0, SIZE) == 0 }
    }
    fn copied(&mut self) -> bool {
        // SAFETY: fixed diagnostic callback, no Rust object/reference escapes.
        unsafe { PublicSnapshotReady() == 1 }
    }
    fn write(&mut self, destination: usize, source: &[u8; 32]) -> bool {
        // SAFETY: live enclave-owned source of exact width. Destination is opaque
        // to Rust; the platform copy checks it. Only explicitly public output.
        unsafe { PublicCopyOut(destination, source.as_ptr(), 32) == 0 }
    }
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
struct Buffers {
    snapshot: [u8; SIZE],
    output: [u8; 32],
}
impl Buffers {
    fn clear(&mut self) {
        if cfg!(probe_skip_request_clear) {
            return;
        }
        let _ = clear_owned_region(&mut self.snapshot);
        let _ = clear_owned_region(&mut self.output);
    }
}
impl Drop for Buffers {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Debug, PartialEq)]
struct Request {
    length: usize,
    destination: usize,
    publish: bool,
}
fn decode(snapshot: &[u8; SIZE]) -> Option<Request> {
    let mut words = [0_u64; 6];
    for (word, bytes) in words.iter_mut().zip(snapshot[..48].chunks_exact(8)) {
        *word = u64::from_le_bytes(bytes.try_into().ok()?);
    }
    let [version, operation, length, destination, width, flags] = words;
    if version != 1 || length > 1024 {
        return None;
    }
    let publish = match operation {
        1 if width == 32
            && destination != 0
            && (flags == PUBLIC || cfg!(probe_implicit_public)) =>
        {
            true
        }
        2 if width == 0 && destination == 0 && flags == 0 => false,
        _ => return None,
    };
    let destination = usize::try_from(destination).ok()?;
    if publish {
        destination.checked_add(32)?;
    }
    Some(Request {
        length: usize::try_from(length).ok()?,
        destination,
        publish,
    })
}

fn operation(
    workspace: &mut Sha256Workspace,
    buffers: &mut Buffers,
    io: &mut impl Transport,
) -> (usize, usize, usize) {
    // Clear the public IV even when request admission fails without using state.
    workspace.with(|state| state.cancel());
    if !io.read(&mut buffers.snapshot) {
        return (11, 0, 0);
    }
    if !io.copied() {
        return (13, 0, 0);
    }
    if cfg!(probe_reread_snapshot) && !io.read(&mut buffers.snapshot) {
        return (11, 0, 0);
    }
    let Some(request) = decode(&buffers.snapshot) else {
        return (10, 0, 0);
    };
    let output = match workspace.with(|mut state| {
        state.update(&buffers.snapshot[48..48 + request.length])?;
        state.finalize_secret(&mut buffers.output)
    }) {
        Ok(output) => output,
        Err(_) => return (14, 0, 0),
    };
    if !workspace_zero(workspace) {
        return (14, 0, 0);
    }
    let mut status = 2;
    let mut exported = 0;
    if request.publish {
        let Ok(bytes) = output.expose().try_into() else {
            return (14, 0, 0);
        };
        if io.write(request.destination, bytes) {
            status = 1;
            exported = 32;
        } else {
            status = 12;
        }
    }
    drop(output);
    if !zero(&buffers.output) {
        return (14, 0, 0);
    }
    (status, request.length, exported)
}

fn within(address: usize, size: usize, low: usize, high: usize) -> bool {
    address >= low && address.checked_add(size).is_some_and(|end| end <= high)
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn PublicRequestWork(source: usize, low: usize, high: usize) -> Report {
    let mut report = Report {
        status: 14,
        snapshot: 0,
        workspace: 0,
        output: 0,
        absorbed: 0,
        cleared: 0,
        exported: 0,
        owner_size: OWNER,
    };
    if high.checked_sub(low) != Some(65536) {
        return report;
    }
    let mut workspace = Sha256Workspace::new();
    let mut buffers = Buffers {
        snapshot: [0; SIZE],
        output: [0; 32],
    };
    report.snapshot = buffers.snapshot.as_ptr() as usize;
    report.workspace = core::ptr::from_ref(&workspace) as usize;
    report.output = buffers.output.as_ptr() as usize;
    if !within(report.snapshot, SIZE, low, high)
        || !within(report.workspace, OWNER, low, high)
        || !within(report.output, 32, low, high)
    {
        return report;
    }
    let (status, absorbed, exported) = operation(&mut workspace, &mut buffers, &mut Native(source));
    buffers.clear();
    report.cleared =
        usize::from(zero(&buffers.snapshot) && zero(&buffers.output) && workspace_zero(&workspace));
    report.status = if report.cleared == 1 { status } else { 14 };
    report.absorbed = absorbed;
    report.exported = exported;
    report
}

#[cfg(test)]
#[path = "window_request_tests.rs"]
mod tests;
