//! Memory-model harness ONLY. Hardware operations are deliberate lifetime
//! doubles, not cryptographic implementations or execution evidence. The actual
//! resident placement/destruction source is copied without runtime edits.
#![allow(dead_code)]
extern crate self as brynja_crypto_cpu;
extern crate self as sha3_batch_accelerated;
use core::cell::Cell;
use core::sync::atomic::{AtomicUsize, Ordering};
static OWNER_DROPS: AtomicUsize = AtomicUsize::new(0);
static AUTHORITY_DROPS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub enum Error {
    Crypto,
    Identity,
}
pub mod static_execution {
    use super::*;
    pub enum Kernel {
        X86Keccak,
    }
    #[repr(align(64))]
    pub struct Authority {
        pub alive: Cell<bool>,
        pub revoked: Cell<bool>,
        padding: [u8; 80],
    }
    impl Authority {
        pub fn new(_: Kernel) -> Result<Self, Error> {
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
}
#[repr(align(128))]
pub struct Owner<'a> {
    authority: &'a static_execution::Authority,
    bytes: [u8; 1024],
}
impl<'a> Owner<'a> {
    pub fn new(authority: &'a static_execution::Authority) -> Result<Self, Error> {
        assert!(authority.alive.get());
        Ok(Self {
            authority,
            bytes: [0x53; 1024],
        })
    }
    pub fn quarantine(&mut self) {
        assert!(self.authority.alive.get());
        self.authority.revoked.set(true);
        self.bytes.fill(0);
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        // The real owner holds borrowed sessions too. This dereference tests
        // destruction ordering and validity; no hashing is simulated here.
        assert!(
            self.authority.alive.get(),
            "authority destroyed before borrowing owner"
        );
        self.bytes.fill(0);
        OWNER_DROPS.fetch_add(1, Ordering::SeqCst);
    }
}
pub mod sha3_batch_accelerated_wire {
    use super::*;
    pub struct Header;
    impl Header {
        pub fn decode(_: usize, header: &[u8; 304]) -> Result<Self, Error> {
            if header[0] == 17 {
                Ok(Self)
            } else {
                Err(Error::Identity)
            }
        }
        pub fn execute(
            self,
            owner: &mut Owner<'_>,
            _: &[u8],
            copy: impl FnOnce(&[u8; 1024]) -> bool,
        ) -> Result<(), Error> {
            assert!(owner.authority.alive.get());
            if owner.authority.revoked.get() || !copy(&owner.bytes) {
                Err(Error::Crypto)
            } else {
                Ok(())
            }
        }
    }
}
mod sha3_batch_accelerated_resident;

#[test]
fn borrowed_lifetime_order_alignment_and_full_page_provenance() {
    use sha3_batch_accelerated_resident::{Page, Resident};
    let mut page = Box::new(Page::empty());
    let mut header = [0; 304];
    header[0] = 17;
    for index in 1..=3 {
        let mut resident = Resident::new(&mut page).unwrap();
        resident
            .execute(0, &header, &[], |bytes| {
                assert_eq!(bytes, &[0x53; 1024]);
                true
            })
            .unwrap();
        resident.quarantine();
        assert!(
            resident
                .execute(0, &header, &[], |_| panic!("revoked copy"))
                .is_err()
        );
        drop(resident);
        assert_eq!(OWNER_DROPS.load(Ordering::SeqCst), index);
        assert_eq!(AUTHORITY_DROPS.load(Ordering::SeqCst), index);
        let pointer = (&*page as *const Page).cast::<u8>();
        for offset in 0..core::mem::size_of::<Page>() {
            // SAFETY: fully initialized 4096-byte page, no resident borrow left.
            assert_eq!(unsafe { pointer.add(offset).read_volatile() }, 0);
        }
    }
}
