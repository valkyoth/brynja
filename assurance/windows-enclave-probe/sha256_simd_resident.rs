//! Private page placement, not OS protection or an enclave host API.
//! The enclosing worker must admit the page, input snapshots and every frame.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use brynja_hash_sha2::hardened_batch::Report;
use core::{marker::PhantomData, mem::MaybeUninit, ptr::NonNull};
pub use sha256_simd::{Algorithm, Error, Lane};
use sha256_simd::{Authority, Kernel, Owner};

const PAGE_BYTES: usize = 4096;
const OWNER_ALIGN: usize = core::mem::align_of::<Owner<'static>>();
const OWNER_OFFSET: usize = core::mem::size_of::<Authority>().next_multiple_of(OWNER_ALIGN);
const _: () = assert!(OWNER_OFFSET + core::mem::size_of::<Owner<'static>>() <= PAGE_BYTES);
const _: () = assert!(core::mem::align_of::<Authority>() <= PAGE_BYTES);
const _: () = assert!(OWNER_ALIGN <= PAGE_BYTES);

/// Movable backing bytes only. A live Resident exclusively borrows the page.
#[repr(align(4096))]
pub struct Page([MaybeUninit<u8>; PAGE_BYTES]);
impl Page {
    pub const fn empty() -> Self {
        Self([MaybeUninit::new(0); PAGE_BYTES])
    }
}

/// No placed reference escapes; authority stays alive until owner destruction.
pub struct Resident<'page> {
    backing: NonNull<u8>,
    authority: NonNull<Authority>,
    owner: NonNull<Owner<'page>>,
    _exclusive: PhantomData<&'page mut Page>,
}
impl<'page> Resident<'page> {
    pub fn new(page: &'page mut Page) -> Result<Self, Error> {
        // Derive both pointers from the entire allocation before any typed borrow.
        let backing = NonNull::from(&mut page.0).cast::<u8>();
        // SAFETY: exclusive, aligned Page borrow; compile-time bounds separate
        // both objects. References are formed only after final placement. All
        // constructor temporaries contain public startup data, not caller input.
        unsafe {
            let authority = backing.cast::<Authority>();
            let owner =
                NonNull::new_unchecked(backing.as_ptr().add(OWNER_OFFSET).cast::<Owner<'page>>());
            let value = match Authority::for_compiled_target(Kernel::Avx2) {
                Ok(value) => value,
                Err(_) => {
                    clear_page(backing);
                    return Err(Error::Backend);
                }
            };
            authority.as_ptr().write(value);
            let state = match Owner::new(&*authority.as_ptr()) {
                Ok(state) => state,
                Err(error) => {
                    authority.as_ptr().drop_in_place();
                    clear_page(backing);
                    return Err(error);
                }
            };
            owner.as_ptr().write(state);
            Ok(Self {
                backing,
                authority,
                owner,
                _exclusive: PhantomData,
            })
        }
    }

    /// Typed copied inputs only; future OS transport must snapshot/admit them.
    pub fn digest(
        &mut self,
        sequence: u64,
        lanes: [Lane<'_>; 8],
        budget: u64,
    ) -> Result<Report, Error> {
        // SAFETY: exclusive access to the initialized unmoved owner; the authority
        // remains live in a disjoint region of the exclusively borrowed page.
        unsafe { self.owner.as_mut() }.digest(sequence, lanes, budget)
    }
    pub fn export_public(
        &mut self,
        sequence: u64,
        plan: [Algorithm; 8],
        copy: impl FnMut(&[u8; 256]) -> bool,
    ) -> Result<(), Error> {
        // SAFETY: same placement invariant; no placed owner reference escapes.
        unsafe { self.owner.as_mut() }.export_public(sequence, plan, copy)
    }
    pub fn cancel(&mut self, sequence: u64) -> Result<(), Error> {
        // SAFETY: same exclusive initialized owner invariant.
        unsafe { self.owner.as_mut() }.cancel(sequence)
    }
    pub fn quarantine(&mut self) {
        // SAFETY: same exclusive initialized owner invariant.
        unsafe { self.owner.as_mut() }.quarantine();
    }
}
impl Drop for Resident<'_> {
    fn drop(&mut self) {
        // SAFETY: destroy borrower before authority; then no live typed object
        // remains, so the original allocation pointer can clear all page bytes.
        unsafe {
            self.owner.as_ptr().drop_in_place();
            self.authority.as_ptr().drop_in_place();
            clear_page(self.backing);
        }
    }
}
unsafe fn clear_page(pointer: NonNull<u8>) {
    for offset in 0..PAGE_BYTES {
        // SAFETY: caller owns the complete page and has destroyed live objects.
        unsafe { pointer.as_ptr().add(offset).write_volatile(0) };
    }
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod sha256_simd_resident_tests;
