//! Safe retained-owner input composition, NOT native residency qualification.
//! Snapshot/workspace/staging must already belong to an admitted worker window.
#![no_std]
#![forbid(unsafe_code)]
use brynja_core::clear_owned_region;
use brynja_hash_sha2::hardened_in_place::Sha256Workspace;
use retained_input::{CAPACITY, HEADER};
use retained_placement::Placed;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Copy,
    Owner(persistent_result::Error),
}

struct Operation<'scope, 'page> {
    owner: &'scope mut Placed<'page>,
    snapshot: &'scope mut [u8; CAPACITY],
    staging: &'scope mut [u8; 32],
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !cfg!(probe_retained_input_skip_clear) {
            let _ = clear_owned_region(self.snapshot);
            let _ = clear_owned_region(self.staging);
        }
        if !self.complete && !cfg!(probe_retained_input_no_quarantine) {
            self.owner.quarantine();
        }
    }
}

/// Trusted fixture seam, not an application callback API. `copy` must be the
/// private platform copy adapter; it may partially write before returning false.
/// Input copying is not atomicity/authentication against a malicious host.
/// All unsuccessful worker attempts quarantine this result owner, even Busy.
pub fn compute(
    owner: &mut Placed<'_>,
    workspace: &mut Sha256Workspace,
    snapshot: &mut [u8; CAPACITY],
    staging: &mut [u8; 32],
    header: &[u8; HEADER],
    expected_sequence: u64,
    mut copy: impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<[u64; 4], Error> {
    // A fresh workspace has a public IV. Clear BEFORE entry, never after hashing
    // as a way to conceal an implementation's failed cleanup.
    workspace.with(|state| state.cancel());
    let mut operation = Operation {
        owner,
        snapshot,
        staging,
        complete: false,
    };
    let _ = clear_owned_region(operation.snapshot);
    let _ = clear_owned_region(operation.staging);
    let (address, length) =
        retained_input::admit(header, expected_sequence).map_err(|_| Error::Header)?;
    if length != 0 {
        let copied = copy(address, &mut operation.snapshot[..length]);
        if !copied && !cfg!(probe_retained_input_ignore_copy) {
            return Err(Error::Copy);
        }
        if cfg!(probe_retained_input_reread) && !copy(address, &mut operation.snapshot[..length]) {
            return Err(Error::Copy);
        }
    }
    let width = if cfg!(probe_retained_input_full_width) {
        CAPACITY
    } else {
        length
    };
    let token = operation
        .owner
        .hash(workspace, operation.staging, &operation.snapshot[..width])
        .map_err(Error::Owner)?;
    operation.complete = true;
    Ok(token)
}
