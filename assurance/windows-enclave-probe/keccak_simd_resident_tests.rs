use super::*;
use brynja_hash_sha3::Fips202BitString;
use keccak_simd::Algorithm;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind},
};
fn plan() -> [Slot; 4] {
    [Slot {
        identity: Algorithm::Sha3_256,
        output_bits: 256,
    }; 4]
}
fn lanes(input: &[u8]) -> [Lane<'_>; 4] {
    plan().map(|slot| Lane {
        slot,
        message: Fips202BitString::new(input, if input.is_empty() { 0 } else { 8 }).unwrap(),
        name: Fips202BitString::new(&[], 0).unwrap(),
        custom: Fips202BitString::new(&[], 0).unwrap(),
    })
}
pub(super) fn cleared(page: &Page) {
    for byte in &page.0 {
        // SAFETY: successful destruction initializes the entire page; the
        // separate strict-provenance Miri model tests this requirement.
        assert_eq!(unsafe { byte.assume_init() }, 0);
    }
}
fn revoked(resident: &mut Resident<'_>) {
    // SAFETY: shared access only to the still-live placed authority.
    assert!(!unsafe { resident.authority.as_ref() }.is_healthy());
    assert!(
        resident
            .export_public(3, plan(), |_| panic!("revoked copy"))
            .is_err()
    );
}
#[test]
fn placement_retained_drop_cancellation_and_recreation() {
    let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
    for mode in 0..3 {
        let base = page.0.as_ptr().addr();
        let mut r = Resident::new(&mut page).unwrap();
        assert_eq!(r.authority.as_ptr().addr(), base);
        assert_eq!(r.owner.as_ptr().addr(), base + OWNER_OFFSET);
        let report = r.digest(1, lanes(&[7; 200]), 8).unwrap();
        assert_eq!(report.kernel, Some(Kernel::Avx2));
        assert_eq!(report.vector_calls, 2);
        if mode == 1 {
            r.cancel(2).unwrap();
        }
        if mode == 2 {
            r.export_public(2, plan(), |out| {
                assert!(out.iter().any(|b| *b != 0));
                true
            })
            .unwrap();
        }
        if mode != 0 {
            r.digest(3, lanes(&[2; 64]), 100).unwrap();
            r.cancel(4).unwrap();
        }
        drop(r);
        cleared(&page);
    }
}
#[test]
fn error_revocation_and_unwind_destroy_the_entire_page() {
    for failure in 0..6 {
        let mut page = Box::new(Page([MaybeUninit::new(0x5a); PAGE_BYTES]));
        let mut r = Resident::new(&mut page).unwrap();
        r.digest(1, lanes(&[3; 200]), 100).unwrap();
        if failure == 3 {
            r.quarantine();
            revoked(&mut r);
        }
        let authority = r.authority;
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut expected = plan();
            if failure == 2 {
                expected[0].identity = Algorithm::Shake256;
            }
            r.export_public(if failure == 4 { 3 } else { 2 }, expected, |_| {
                if failure == 1 {
                    panic!("copy unwind");
                }
                if failure == 5 {
                    // SAFETY: shared access during callback, no mutable authority borrow.
                    unsafe { authority.as_ref() }.quarantine();
                }
                failure == 5
            })
        }));
        assert!(matches!(result, Err(_) | Ok(Err(_))));
        revoked(&mut r);
        drop(r);
        cleared(&page);
    }
}
#[test]
fn work_and_bounds_failure_clear_before_page_reuse() {
    for mode in 0..4 {
        let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
        let mut r = Resident::new(&mut page).unwrap();
        let result = match mode {
            0 => r.digest(1, lanes(&[0; 200]), 7),
            1 => r.digest(1, lanes(&[0; 1025]), 100),
            2 => r.digest(1, lanes(&[0; 64]), 0),
            _ => r.digest(2, lanes(&[0; 64]), 100),
        };
        assert!(result.is_err());
        revoked(&mut r);
        drop(r);
        cleared(&page);
        let mut r = Resident::new(&mut page).unwrap();
        r.digest(1, lanes(&[9; 64]), 100).unwrap();
        drop(r);
        cleared(&page);
    }
}
