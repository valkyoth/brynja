//! Private placement component, not an enclave admission API.
//! The future OS adapter must admit/reside the backing page and all worker
//! frames. Native component tests alone do not establish that property.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use core::{marker::PhantomData, mem::MaybeUninit, ptr::NonNull};
use kmac_accelerated::{Error, Owner, kmac_accelerated_wire::Header as Request};

const PAGE_BYTES: usize = 4096;
const OWNER_ALIGN: usize = core::mem::align_of::<Owner<'static>>();
const OWNER_OFFSET: usize = core::mem::size_of::<Authority>().next_multiple_of(OWNER_ALIGN);
const _: () = assert!(OWNER_OFFSET + core::mem::size_of::<Owner<'static>>() <= PAGE_BYTES);
const _: () = assert!(core::mem::align_of::<Authority>() <= PAGE_BYTES);
const _: () = assert!(OWNER_ALIGN <= PAGE_BYTES);

/// Only backing bytes, never a moveable live self-referential object. The
/// exclusive borrow held by Resident prevents moving or accessing this page
/// until both placed objects have been destroyed.
#[repr(align(4096))]
pub struct Page([MaybeUninit<u8>; PAGE_BYTES]);
impl Page {
    pub const fn empty() -> Self {
        Self([MaybeUninit::new(0); PAGE_BYTES])
    }
}

/// Carries only pointers into a borrowed page. It exposes neither placed
/// object, so safe callers cannot extract a stream then destroy its authority.
pub struct Resident<'page> {
    backing: NonNull<u8>,
    authority: NonNull<Authority>,
    owner: NonNull<Owner<'page>>,
    _exclusive: PhantomData<&'page mut Page>,
}

impl<'page> Resident<'page> {
    pub fn new(page: &'page mut Page) -> Result<Self, Error> {
        // Take the single backing pointer before creating any placed references.
        // Never reborrow the entire page while either placed object is alive.
        let backing = NonNull::from(&mut page.0).cast::<u8>();
        // SAFETY: Page supplies initialized, aligned, exclusive storage for the
        // entire borrow. Compile-time bounds keep both nonoverlapping objects
        // inside it. No reference to the initialized Authority is made until
        // after its final placement. Constructor temporaries contain public KAT
        // data only, not caller input.
        unsafe {
            let authority = backing.cast::<Authority>();
            let owner =
                NonNull::new_unchecked(backing.as_ptr().add(OWNER_OFFSET).cast::<Owner<'page>>());
            let value = match Authority::new(Kernel::X86Keccak) {
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

    /// A fixed copied header and separately copied payload, never raw host
    /// pointers. Rejected decoding revokes existing retained state too.
    pub fn execute(
        &mut self,
        operation: usize,
        header: &[u8; 112],
        input: &[u8],
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        // SAFETY: exclusive Resident borrow, initialized unmoved owner in the
        // borrowed page; no owner or authority references escape this method.
        let owner = unsafe { self.owner.as_mut() };
        match Request::decode(operation, header) {
            Ok(request) => request.execute(owner, input, copy),
            Err(error) => {
                owner.quarantine();
                Err(error)
            }
        }
    }

    pub fn quarantine(&mut self) {
        // SAFETY: same exclusive placed-owner invariant as execute.
        unsafe { self.owner.as_mut() }.quarantine();
    }
}

impl Drop for Resident<'_> {
    fn drop(&mut self) {
        // SAFETY: no operation borrow survives this exclusive drop. Destroy the
        // borrowing stream before its authority. Only then reuse the raw backing
        // pointer to clear padding and inactive variant bytes across the page.
        unsafe {
            self.owner.as_ptr().drop_in_place();
            self.authority.as_ptr().drop_in_place();
            clear_page(self.backing);
        }
    }
}

unsafe fn clear_page(pointer: NonNull<u8>) {
    for offset in 0..PAGE_BYTES {
        // SAFETY: caller owns the full writable backing page with no live typed
        // objects or references left; every offset is inside that allocation.
        unsafe { pointer.as_ptr().add(offset).write_volatile(0) };
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod kmac_accelerated_resident_tests;
