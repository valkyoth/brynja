//! Public-vector research adapter. No platform admission or application callbacks.
#![no_std]
#![forbid(unsafe_code)]
use brynja_core::clear_owned_region;
use brynja_hash_sha2::hardened_in_place::Sha256Workspace;
use persistent_result::{Error, Slot};

pub struct Owner<'storage> {
    slot: Slot<'storage>,
}

struct Staging<'a>(&'a mut [u8; 32]);
impl Drop for Staging<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0);
    }
}

impl<'storage> Owner<'storage> {
    pub fn new(bytes: &'storage mut [u8; 32], identity: [u64; 2]) -> Result<Self, Error> {
        Ok(Self {
            slot: Slot::new(bytes, identity)?,
        })
    }

    /// Both staging and persistent destination must be independently admitted
    /// before use. The intermediate remains secret-owned until after its copy
    /// into the retained slot; no public digest/finalization API is used.
    pub fn hash(
        &mut self,
        workspace: &mut Sha256Workspace,
        staging: &mut [u8; 32],
        input: &[u8],
    ) -> Result<[u64; 4], Error> {
        let _ = clear_owned_region(staging);
        let staging = Staging(staging);
        self.slot.fill(|destination| {
            workspace
                .with(|mut state| {
                    state.update(input)?;
                    let output = state.finalize_secret(staging.0)?;
                    destination.copy_from_slice(output.expose());
                    Ok::<(), brynja_hash_sha2::HardenedSha2Error>(())
                })
                .is_ok()
        })
    }

    pub fn export_public(
        &mut self,
        token: [u64; 4],
        flag: u64,
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        self.slot.export_public(token, flag, copy)
    }

    pub fn cancel(&mut self, token: [u64; 4]) -> Result<(), Error> {
        self.slot.cancel(token)
    }

    pub fn quarantine(&mut self) {
        self.slot.quarantine();
    }
    pub fn close(&mut self) {
        self.slot.close();
    }
}

#[cfg(test)]
#[path = "retained_digest_tests.rs"]
mod tests;
