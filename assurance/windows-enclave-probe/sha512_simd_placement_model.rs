//! Placement-only lifetime doubles: no cryptography or enclave execution.
#![allow(dead_code)]
extern crate self as brynja_hash_sha2;
extern crate self as sha512_simd;
use core::{
    cell::Cell,
    sync::atomic::{AtomicUsize, Ordering},
};
static OWNER_DROPS: AtomicUsize = AtomicUsize::new(0);
static AUTHORITY_DROPS: AtomicUsize = AtomicUsize::new(0);
static FAIL_CONSTRUCTION: AtomicUsize = AtomicUsize::new(0);
#[derive(Debug)]
pub enum Error {
    Backend,
}
pub enum Kernel {
    Avx2,
}
pub type Algorithm = u8;
pub struct Lane<'a> {
    pub identity: Algorithm,
    pub bytes: &'a [u8],
    pub last: u8,
}
pub mod hardened_batch512 {
    pub struct Report;
}
#[repr(align(64))]
pub struct Authority {
    alive: Cell<bool>,
    revoked: Cell<bool>,
    padding: [u8; 80],
}
impl Authority {
    pub fn for_compiled_target(_: Kernel) -> Result<Self, Error> {
        if FAIL_CONSTRUCTION.load(Ordering::SeqCst) == 1 {
            return Err(Error::Backend);
        }
        Ok(Self {
            alive: Cell::new(true),
            revoked: Cell::new(false),
            padding: [0x17; 80],
        })
    }
}
impl Drop for Authority {
    fn drop(&mut self) {
        assert!(self.alive.get());
        self.alive.set(false);
        AUTHORITY_DROPS.fetch_add(1, Ordering::SeqCst);
    }
}
#[repr(align(128))]
pub struct Owner<'a> {
    authority: &'a Authority,
    bytes: [u8; 256],
}
impl<'a> Owner<'a> {
    pub fn new(authority: &'a Authority) -> Result<Self, Error> {
        assert!(authority.alive.get());
        if FAIL_CONSTRUCTION.load(Ordering::SeqCst) == 2 {
            return Err(Error::Backend);
        }
        Ok(Self {
            authority,
            bytes: [0x53; 256],
        })
    }
    pub fn digest(
        &mut self,
        _: u64,
        _: [Lane<'_>; 4],
        _: u64,
    ) -> Result<hardened_batch512::Report, Error> {
        assert!(self.authority.alive.get());
        if self.authority.revoked.get() {
            return Err(Error::Backend);
        }
        self.bytes.fill(0x73);
        Ok(hardened_batch512::Report)
    }
    pub fn export_public(
        &mut self,
        _: u64,
        _: [Algorithm; 4],
        mut copy: impl FnMut(&[u8; 256]) -> bool,
    ) -> Result<(), Error> {
        assert!(self.authority.alive.get());
        if self.authority.revoked.get() || !copy(&self.bytes) {
            Err(Error::Backend)
        } else {
            Ok(())
        }
    }
    pub fn cancel(&mut self, _: u64) -> Result<(), Error> {
        assert!(self.authority.alive.get());
        self.bytes.fill(0);
        Ok(())
    }
    pub fn quarantine(&mut self) {
        assert!(self.authority.alive.get());
        self.authority.revoked.set(true);
        self.bytes.fill(0);
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        assert!(
            self.authority.alive.get(),
            "authority destroyed before borrowing owner"
        );
        self.bytes.fill(0);
        OWNER_DROPS.fetch_add(1, Ordering::SeqCst);
    }
}
mod sha512_simd_resident;
use sha512_simd_resident::{Page, Resident};
fn cleared(page: &Page) {
    let pointer = (page as *const Page).cast::<u8>();
    for offset in 0..core::mem::size_of::<Page>() {
        // SAFETY: successful destruction or rollback must initialize all bytes;
        // Miri checks this full-allocation provenance and initialization claim.
        assert_eq!(unsafe { pointer.add(offset).read_volatile() }, 0);
    }
}
#[test]
fn borrowed_lifetime_order_alignment_and_full_page_provenance() {
    let mut page = Box::new(Page::empty());
    for failure in 1..=2 {
        FAIL_CONSTRUCTION.store(failure, Ordering::SeqCst);
        let pointer = (&mut *page as *mut Page).cast::<u8>();
        for offset in 0..core::mem::size_of::<Page>() {
            // SAFETY: exclusive backing bytes, no live objects exist yet.
            unsafe { pointer.add(offset).write(0xa5) };
        }
        assert!(Resident::new(&mut page).is_err());
        cleared(&page);
        assert_eq!(OWNER_DROPS.load(Ordering::SeqCst), 0);
        assert_eq!(AUTHORITY_DROPS.load(Ordering::SeqCst), failure - 1);
    }
    FAIL_CONSTRUCTION.store(0, Ordering::SeqCst);
    AUTHORITY_DROPS.store(0, Ordering::SeqCst);
    for index in 1..=3 {
        let mut resident = Resident::new(&mut page).unwrap();
        resident
            .digest(
                1,
                [0; 4].map(|identity| Lane {
                    identity,
                    bytes: &[],
                    last: 0,
                }),
                0,
            )
            .unwrap();
        resident
            .export_public(2, [0; 4], |bytes| {
                assert_eq!(bytes, &[0x73; 256]);
                true
            })
            .unwrap();
        resident.cancel(3).unwrap();
        resident.quarantine();
        assert!(
            resident
                .export_public(4, [0; 4], |_| panic!("revoked copy"))
                .is_err()
        );
        drop(resident);
        assert_eq!(OWNER_DROPS.load(Ordering::SeqCst), index);
        assert_eq!(AUTHORITY_DROPS.load(Ordering::SeqCst), index);
        cleared(&page);
    }
}
