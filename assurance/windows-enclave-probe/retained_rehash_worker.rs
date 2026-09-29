//! Fixed private native composition operation, not application callbacks.
use super::{Placed, Sha256Workspace, within};
unsafe extern "C" {
    fn PublicRehashObserve(values: *const usize) -> i32;
}
fn zero(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| unsafe { core::ptr::read_volatile(byte) == 0 })
}
fn compute(
    owner: &mut Placed<'_>,
    token: [u64; 4],
    workspace: &mut Sha256Workspace,
    candidate: &mut [u8; 32],
    staging: &mut [u8; 32],
) -> (usize, Option<[u64; 4]>) {
    let result = owner.rehash(token, workspace, candidate, staging);
    // SAFETY: source-bound initialized byte-array layout, no representation
    // padding, exclusive operation ended. Do not mask cleanup with an extra wipe.
    let bytes =
        unsafe { core::slice::from_raw_parts(core::ptr::from_ref(workspace).cast::<u8>(), 1170) };
    if !zero(bytes) || !zero(candidate) || !zero(staging) {
        owner.quarantine();
        return (191, None);
    }
    match result {
        Ok(next) => (8, Some(next)),
        Err(error) => (super::code(Err(error), 0), None),
    }
}
#[inline(never)]
pub(super) fn rehash(
    owner: &mut Placed<'_>,
    token: [u64; 4],
    epoch: u64,
    low: usize,
    high: usize,
) -> (usize, Option<[u64; 4]>) {
    let mut workspace = Sha256Workspace::new();
    let mut candidate = [0; 32];
    let mut staging = [0; 32];
    let mut report = [
        core::ptr::from_ref(&workspace).addr(),
        candidate.as_ptr().addr(),
        staging.as_ptr().addr(),
        0,
        token[2] as usize,
        0,
        epoch as usize,
        0,
    ];
    if high.checked_sub(low) != Some(65536)
        || !within(report[0], 1170, low, high)
        || !within(report[1], 32, low, high)
        || !within(report[2], 32, low, high)
        || !within(
            report.as_ptr().addr(),
            core::mem::size_of_val(&report),
            low,
            high,
        )
    {
        owner.quarantine();
        return (190, None);
    }
    let (status, next) = compute(owner, token, &mut workspace, &mut candidate, &mut staging);
    report[3] = usize::from(status != 191);
    report[5] = next.map_or(0, |value| value[2] as usize);
    report[7] = status;
    // SAFETY: initialized bounded metadata array in admitted worker storage.
    if unsafe { PublicRehashObserve(report.as_ptr()) } != 1 {
        owner.quarantine();
        return (191, None);
    }
    (status | (1_usize << 32), next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;
    use persistent_result::{Error, PUBLIC_OUTPUT};
    #[repr(align(4096))]
    struct Page([MaybeUninit<u8>; 4096]);
    #[unsafe(no_mangle)]
    extern "C" fn PublicRehashObserve(_: *const usize) -> i32 {
        1
    }
    #[test]
    fn native_composition_checks_scratch_before_accepting_result() {
        let mut page = Page([MaybeUninit::new(0); 4096]);
        let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
        let mut workspace = Sha256Workspace::new();
        let mut candidate = [0xa5; 32];
        let mut staging = [0xa5; 32];
        let token = owner.hash(&mut workspace, &mut staging, b"abc").unwrap();
        let (status, next) = compute(
            &mut owner,
            token,
            &mut workspace,
            &mut candidate,
            &mut staging,
        );
        assert_eq!(status, 8);
        assert_eq!(next.unwrap()[2], token[2] + 1);
        assert_eq!(candidate, [0; 32]);
        assert_eq!(staging, [0; 32]);
        let (status, next) = compute(
            &mut owner,
            token,
            &mut workspace,
            &mut candidate,
            &mut staging,
        );
        assert_eq!(status, 103);
        assert!(next.is_none());
        assert_eq!(
            owner.export_public(token, PUBLIC_OUTPUT, |_| panic!("stale")),
            Err(Error::Quarantined)
        );
    }
}
