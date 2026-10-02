use super::*;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind},
};
fn plan() -> [Algorithm; 4] {
    [
        Algorithm::Sha384,
        Algorithm::Sha512,
        Algorithm::Sha512_224,
        Algorithm::Sha512_256,
    ]
}
fn lanes(input: &[u8]) -> [Lane<'_>; 4] {
    plan().map(|identity| Lane {
        identity,
        bytes: input,
        last: 8,
    })
}
fn cleared(page: &Page) {
    for byte in &page.0 {
        // SAFETY: after resident destruction, the full-page wipe initializes all
        // bytes. The placement-only strict-provenance Miri model checks this.
        assert_eq!(unsafe { byte.assume_init() }, 0);
    }
}
fn revoked(resident: &mut Resident<'_>) {
    // SAFETY: short shared borrow of still-live authority; no mutable borrow.
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
        let report = r.digest(1, lanes(&[7; 257]), 100).unwrap();
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
            r.digest(3, lanes(&[2; 128]), 100).unwrap();
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
        r.digest(1, lanes(&[3; 129]), 100).unwrap();
        if failure == 3 {
            r.quarantine();
            revoked(&mut r);
        }
        let authority = r.authority;
        let result = catch_unwind(AssertUnwindSafe(|| {
            r.export_public(
                if failure == 4 { 3 } else { 2 },
                if failure == 2 {
                    [Algorithm::Sha512; 4]
                } else {
                    plan()
                },
                |_| {
                    if failure == 1 {
                        panic!("copy unwind");
                    }
                    if failure == 5 {
                        // SAFETY: only shared authority access during a callback;
                        // the placed authority is alive and no mutable borrow exists.
                        unsafe { authority.as_ref() }.quarantine();
                    }
                    failure == 5
                },
            )
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
            0 => r.digest(1, lanes(&[0; 127]), 100),
            1 => r.digest(1, lanes(&[0; 1025]), 100),
            2 => r.digest(1, lanes(&[0; 128]), 0),
            _ => r.digest(2, lanes(&[0; 128]), 100),
        };
        assert!(result.is_err());
        revoked(&mut r);
        drop(r);
        cleared(&page);
        let mut r = Resident::new(&mut page).unwrap();
        r.digest(1, lanes(&[9; 128]), 100).unwrap();
        drop(r);
        cleared(&page);
    }
}
