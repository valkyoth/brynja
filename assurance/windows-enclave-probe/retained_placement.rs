//! Isolated placement boundary, not platform admission or a shipping API.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use brynja_hash_sha2::hardened_in_place::Sha256Workspace;
use core::{marker::PhantomData, mem::MaybeUninit, ptr::NonNull};
use persistent_result::Error;
use retained_digest::Owner;

pub const PAGE: usize = 4096;
const OWNER_OFFSET: usize = 256;
const _: () = assert!(OWNER_OFFSET >= 32);
const _: () = assert!(OWNER_OFFSET + core::mem::size_of::<Owner<'static>>() <= PAGE);
const _: () = assert!(OWNER_OFFSET % core::mem::align_of::<Owner<'static>>() == 0);
const _: () = assert!(PAGE % core::mem::align_of::<Owner<'static>>() == 0);

#[derive(Debug, PartialEq, Eq)]
pub enum PlacementError {
    Geometry,
    Identity,
}

/// Exclusively borrows one external page. The caller must separately establish
/// enclave membership/residency and must not release that residency before Drop.
/// This object can move; neither the page nor its in-place owner moves with it.
/// Forgetting this object does not run cleanup and is not a release receipt.
pub struct Placed<'page> {
    owner: NonNull<Owner<'page>>,
    page: NonNull<u8>,
    borrow: PhantomData<&'page mut [MaybeUninit<u8>]>,
}

impl<'page> Placed<'page> {
    pub fn new(
        page: &'page mut [MaybeUninit<u8>],
        identity: [u64; 2],
    ) -> Result<Self, PlacementError> {
        if page.len() != PAGE || page.as_ptr().addr() % PAGE != 0 {
            return Err(PlacementError::Geometry);
        }
        // Nonempty exclusive slice guarantees a live, nonnull allocation. No
        // reference to the full page is retained alongside its typed subobjects.
        let base = NonNull::from(&mut *page).cast::<u8>();
        // SAFETY: the entire exclusively borrowed page is writable. Initialize
        // bytes without reading uninitialized memory, including future padding.
        unsafe { erase(base) };
        // SAFETY: bytes 0..32 are initialized, exclusive, byte-aligned and
        // disjoint from the owner at 256. Their borrow lasts until owner Drop.
        let bytes = unsafe { &mut *base.as_ptr().cast::<[u8; 32]>() };
        let owner = Owner::new(bytes, identity).map_err(|_| PlacementError::Identity)?;
        // SAFETY: checked exact page alignment and static layout bounds ensure
        // this location is aligned, in-bounds and disjoint from result storage.
        let pointer = unsafe { base.as_ptr().add(OWNER_OFFSET).cast::<Owner<'page>>() };
        // SAFETY: this is the unique first initialization of fresh placement
        // storage. Only metadata moves; the borrowed result bytes stay in place.
        unsafe { pointer.write(owner) };
        Ok(Self {
            // SAFETY: derived in-bounds from a nonnull live allocation.
            owner: unsafe { NonNull::new_unchecked(pointer) },
            page: base,
            borrow: PhantomData,
        })
    }

    fn owner(&mut self) -> &mut Owner<'page> {
        // SAFETY: initialized exactly once, exclusively reached through &mut
        // self, never moved out; page borrow outlives this reborrow.
        unsafe { self.owner.as_mut() }
    }

    pub fn hash(
        &mut self,
        workspace: &mut Sha256Workspace,
        staging: &mut [u8; 32],
        input: &[u8],
    ) -> Result<[u64; 4], Error> {
        self.owner().hash(workspace, staging, input)
    }

    /// Trusted fixture seam only; native integration must use fixed OS copy-out.
    pub fn export_public(
        &mut self,
        token: [u64; 4],
        flag: u64,
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        self.owner().export_public(token, flag, copy)
    }

    pub fn cancel(&mut self, token: [u64; 4]) -> Result<(), Error> {
        self.owner().cancel(token)
    }

    pub fn quarantine(&mut self) {
        self.owner().quarantine();
    }
}

// SAFETY requirement: a live exclusive writable PAGE-byte allocation with no
// live typed objects/references whose representation this write would invalidate.
unsafe fn erase(page: NonNull<u8>) {
    for offset in 0..PAGE {
        // SAFETY: caller provides the entire exclusively writable page.
        unsafe { page.as_ptr().add(offset).write_volatile(0) };
    }
}

impl Drop for Placed<'_> {
    fn drop(&mut self) {
        // SAFETY: unique initialized owner, no outstanding operation borrow.
        // Crucially, destroy its reference-bearing representation BEFORE wiping
        // the page. Erasing a live Owner would make its destructor invalid.
        unsafe { self.owner.as_ptr().drop_in_place() };
        #[cfg(test)]
        {
            // SAFETY: owner and its exclusive borrow have ended. Result bytes
            // were initialized at construction; no padding is read here.
            let result = unsafe { core::slice::from_raw_parts(self.page.as_ptr(), 32) };
            assert!(
                result.iter().all(|byte| *byte == 0),
                "owner must clear before page erase"
            );
        }
        // SAFETY: typed owner and all its internal borrows have ended. Clear
        // every byte (including metadata/padding) before returning the page.
        unsafe { erase(self.page) };
    }
}

#[cfg(test)]
#[path = "retained_placement_tests.rs"]
mod tests;
