//! Private module included by the generated retained-worker crate.
use super::{Placed, Sha256Workspace, within};
use retained_input::{CAPACITY, HEADER};

unsafe extern "C" {
    fn PublicInputSource() -> usize;
    fn PublicInputCopy(kind: usize, destination: *mut u8, source: usize, length: usize) -> i32;
    fn PublicInputObserve(values: *const usize) -> i32;
}
struct Buffers {
    header: [u8; HEADER],
    snapshot: [u8; CAPACITY],
    staging: [u8; 32],
}
struct Guard<'a, 'page> {
    owner: &'a mut Placed<'page>,
    buffers: &'a mut Buffers,
    complete: bool,
}
impl Drop for Guard<'_, '_> {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(&mut self.buffers.header);
        let _ = brynja_core::clear_owned_region(&mut self.buffers.snapshot);
        let _ = brynja_core::clear_owned_region(&mut self.buffers.staging);
        if !self.complete {
            self.owner.quarantine();
        }
    }
}
trait CopyInput {
    fn read(&mut self, kind: usize, address: usize, bytes: &mut [u8]) -> bool;
}
struct Native;
impl CopyInput for Native {
    fn read(&mut self, kind: usize, address: usize, bytes: &mut [u8]) -> bool {
        // SAFETY: exclusive initialized destination was checked inside the admitted
        // worker. Only the OS copy primitive dereferences the opaque host address.
        unsafe { PublicInputCopy(kind, bytes.as_mut_ptr(), address, bytes.len()) == 0 }
    }
}
fn zero(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| unsafe { core::ptr::read_volatile(byte) == 0 })
}
fn workspace_zero(workspace: &Sha256Workspace) -> bool {
    // SAFETY: source-bound builder checks initialized byte arrays and exact
    // layout (1170 bytes, alignment 1), excluding padding; operation borrow ended.
    zero(unsafe { core::slice::from_raw_parts(core::ptr::from_ref(workspace).cast(), 1170) })
}
fn receive(
    owner: &mut Placed<'_>,
    workspace: &mut Sha256Workspace,
    buffers: &mut Buffers,
    source: usize,
    expected: u64,
    copy: &mut impl CopyInput,
) -> (usize, usize, Option<[u64; 4]>) {
    workspace.with(|state| state.cancel());
    let mut guard = Guard {
        owner,
        buffers,
        complete: false,
    };
    if !copy.read(0, source, &mut guard.buffers.header) {
        return (121, 0, None);
    }
    // This diagnostic mutant deliberately makes sequence validation vacuous.
    let expected = if cfg!(probe_retained_input_trust_header) {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&guard.buffers.header[8..16]);
        u64::from_le_bytes(bytes)
    } else {
        expected
    };
    let length = retained_input::admit(&guard.buffers.header, expected).map_or(0, |(_, n)| n);
    let result = retained_borrowed::compute(
        guard.owner,
        workspace,
        &mut guard.buffers.snapshot,
        &mut guard.buffers.staging,
        &guard.buffers.header,
        expected,
        |address, bytes| usize::try_from(address).is_ok_and(|address| copy.read(1, address, bytes)),
    );
    // Check component cleanup BEFORE this wrapper's defense-in-depth wipe runs.
    if !zero(&guard.buffers.snapshot) || !zero(&guard.buffers.staging) || !workspace_zero(workspace)
    {
        return (191, length, None);
    }
    match result {
        Ok(token) => {
            guard.complete = true;
            (2, length, Some(token))
        }
        Err(retained_borrowed::Error::Header) => (120, 0, None),
        Err(retained_borrowed::Error::Copy) => (121, length, None),
        Err(retained_borrowed::Error::Owner(error)) => (super::code(Err(error), 0), length, None),
    }
}

#[inline(never)]
pub(super) fn hash(
    owner: &mut Placed<'_>,
    expected: u64,
    low: usize,
    high: usize,
) -> (usize, Option<[u64; 4]>) {
    let mut workspace = Sha256Workspace::new();
    let mut buffers = Buffers {
        header: [0; HEADER],
        snapshot: [0; CAPACITY],
        staging: [0; 32],
    };
    let mut observed = [
        buffers.header.as_ptr().addr(),
        buffers.snapshot.as_ptr().addr(),
        core::ptr::from_ref(&workspace).addr(),
        buffers.staging.as_ptr().addr(),
        0,
        0,
        expected as usize,
    ];
    if high.checked_sub(low) != Some(65536)
        || !within(observed[0], HEADER, low, high)
        || !within(observed[1], CAPACITY, low, high)
        || !within(observed[2], 1170, low, high)
        || !within(observed[3], 32, low, high)
        || !within(
            observed.as_ptr().addr(),
            core::mem::size_of_val(&observed),
            low,
            high,
        )
    {
        owner.quarantine();
        return (190, None);
    }
    // SAFETY: fixed private C accessor returns routing metadata only during entry.
    let source = unsafe { PublicInputSource() };
    let (status, length, token) = receive(
        owner,
        &mut workspace,
        &mut buffers,
        source,
        expected,
        &mut Native,
    );
    observed[4] = length;
    observed[5] = usize::from(
        zero(&buffers.header)
            && zero(&buffers.snapshot)
            && zero(&buffers.staging)
            && workspace_zero(&workspace),
    );
    // SAFETY: initialized fixed seven-word report, live in the admitted worker.
    if observed[5] != 1 || unsafe { PublicInputObserve(observed.as_ptr()) } != 1 {
        owner.quarantine();
        return (191, None);
    }
    (status | (1_usize << 32), token)
}

#[cfg(test)]
#[path = "retained_borrowed_worker_tests.rs"]
mod tests;
