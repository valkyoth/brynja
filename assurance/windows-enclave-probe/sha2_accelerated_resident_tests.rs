use super::*;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind},
};

fn header(sequence: u64, identity: u64, length: u64, last: u64) -> [u8; 64] {
    let mut header = [0; 64];
    for (slot, value) in header.chunks_exact_mut(8).zip([
        13,
        sequence,
        identity,
        length,
        last,
        if length == 0 { 0 } else { 4096 },
        1,
        0,
    ]) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    header
}

fn assert_cleared(page: &Page) {
    for byte in &page.0 {
        // SAFETY: each test has just destroyed its Resident, whose full-page
        // wipe must initialize every byte, including object padding. The
        // separate memory-model test detects uninitialized reads if it does not.
        assert_eq!(unsafe { byte.assume_init() }, 0);
    }
}

fn retained(resident: &mut Resident<'_>) {
    resident
        .execute(11, &header(1, 2, 0, 0), &[], |_| panic!("begin exported"))
        .unwrap();
    resident
        .execute(13, &header(2, 0, 3, 8), b"abc", |_| {
            panic!("finish exported")
        })
        .unwrap();
}

#[test]
fn stream_and_authority_are_placed_then_destroyed_before_full_clear() {
    let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
    let base = page.0.as_ptr().addr();
    for _ in 0..3 {
        let mut resident = Resident::new(&mut page).unwrap();
        assert_eq!(resident.authority.as_ptr().addr(), base);
        assert_eq!(resident.owner.as_ptr().addr(), base + OWNER_OFFSET);
        retained(&mut resident);
        let expected = brynja_hash_sha2::sha256(b"abc").unwrap();
        resident
            .execute(15, &header(3, 2, 0, 0), &[], |bytes| {
                assert_eq!(bytes, expected.as_bytes());
                true
            })
            .unwrap();
        drop(resident);
        assert_cleared(&page);
    }
}

#[test]
fn retained_and_streaming_drop_clear_without_export() {
    for finish in [false, true] {
        let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
        let mut resident = Resident::new(&mut page).unwrap();
        resident
            .execute(11, &header(1, 1, 0, 0), &[], |_| false)
            .unwrap();
        resident
            .execute(
                if finish { 13 } else { 12 },
                &header(2, 0, 3, 8),
                b"abc",
                |_| false,
            )
            .unwrap();
        drop(resident);
        assert_cleared(&page);
    }
}

#[test]
fn bad_decode_copy_failure_and_unwind_revoke_and_clear() {
    for failure in 0..4 {
        let mut page = Box::new(Page([MaybeUninit::new(0xa5); PAGE_BYTES]));
        let mut resident = Resident::new(&mut page).unwrap();
        retained(&mut resident);
        let mut request = header(3, 2, 0, 0);
        if failure == 0 {
            request[0] = 6;
        }
        if failure == 1 {
            request[48] = 0;
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            resident.execute(15, &request, &[], |_| {
                if failure == 3 {
                    panic!("test output failure");
                }
                false
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        // A rejected header must not leave previously retained output releasable.
        assert!(
            resident
                .execute(15, &header(3, 2, 0, 0), &[], |_| panic!("revoked export"))
                .is_err()
        );
        // SAFETY: a test-only shared read of the still-live placed authority;
        // no mutable authority reference exists and this borrow ends here.
        assert!(unsafe { resident.authority.as_ref() }.session().is_err());
        drop(resident);
        assert_cleared(&page);
    }
}

#[test]
fn explicit_quarantine_is_terminal_even_for_cancel() {
    let mut page = Box::new(Page::empty());
    let mut resident = Resident::new(&mut page).unwrap();
    retained(&mut resident);
    resident.quarantine();
    assert!(
        resident
            .execute(16, &header(3, 0, 0, 0), &[], |_| false)
            .is_err()
    );
    drop(resident);
    assert_cleared(&page);
}
