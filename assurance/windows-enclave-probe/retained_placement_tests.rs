extern crate std;
use super::*;
use persistent_result::PUBLIC_OUTPUT;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[repr(C, align(4096))]
struct Pages([MaybeUninit<u8>; PAGE * 3]);
impl Pages {
    fn new() -> Self {
        Self([MaybeUninit::new(0xa5); PAGE * 3])
    }
    fn middle(&mut self) -> &mut [MaybeUninit<u8>] {
        &mut self.0[PAGE..PAGE * 2]
    }
    fn check(&self, cleared: bool) {
        for (index, byte) in self.0.iter().enumerate() {
            // Do not interpret a destroyed Rust object's padding, including in
            // deliberately broken no-page-wipe mutants.
            if cleared
                && (PAGE + OWNER_OFFSET..PAGE + OWNER_OFFSET + core::mem::size_of::<Owner<'_>>())
                    .contains(&index)
            {
                continue;
            }
            let expected = if cleared && (PAGE..PAGE * 2).contains(&index) {
                0
            } else {
                0xa5
            };
            // SAFETY: test initializes every byte and placement only writes.
            assert_eq!(unsafe { byte.assume_init() }, expected, "byte {index}");
        }
    }
}

fn hash(owner: &mut Placed<'_>) -> [u64; 4] {
    // SAFETY: unused byte disjoint from both initialized objects; test-only
    // canary makes the final page wipe independently observable without ever
    // reading Rust representation padding in a broken mutant.
    unsafe { owner.page.as_ptr().add(128).write(0x5a) };
    let mut workspace = Sha256Workspace::new();
    let mut staging = [0xa5; 32];
    let token = owner.hash(&mut workspace, &mut staging, b"abc").unwrap();
    assert_eq!(staging, [0; 32]);
    token
}

#[test]
fn retained_digest_survives_metadata_move_and_worker_return() {
    let mut pages = Pages::new();
    let mut owner = Placed::new(pages.middle(), [7, 9]).unwrap();
    let token = hash(&mut owner);
    let mut moved = owner;
    moved
        .export_public(token, PUBLIC_OUTPUT, |bytes| {
            assert_eq!(
                bytes,
                &[
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                    0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                    0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
                ]
            );
            true
        })
        .unwrap();
    assert_eq!(moved.cancel(token), Err(Error::Spent));
    let next = hash(&mut moved);
    assert_ne!(next, token);
    moved.cancel(next).unwrap();
    drop(moved);
    pages.check(true);
}

#[test]
fn destruction_clears_ready_result_before_page_release_and_reuse() {
    let mut pages = Pages::new();
    for _ in 0..3 {
        let mut owner = Placed::new(pages.middle(), [7, 9]).unwrap();
        let _abandoned = hash(&mut owner);
        drop(owner);
        pages.check(true);
    }
}

#[test]
fn failed_copy_and_unwind_drop_owner_before_erasing_page() {
    for unwind in [false, true] {
        let mut pages = Pages::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut owner = Placed::new(pages.middle(), [7, 9]).unwrap();
            let token = hash(&mut owner);
            let result = owner.export_public(token, PUBLIC_OUTPUT, |_| {
                assert!(!unwind, "controlled copy unwind");
                false
            });
            assert_eq!(result, Err(Error::Copy));
            assert_eq!(owner.cancel(token), Err(Error::Quarantined));
        }));
        assert_eq!(result.is_err(), unwind);
        pages.check(true);
    }
}

#[test]
fn rejects_geometry_without_writing_and_identity_after_clearing() {
    let mut pages = Pages::new();
    for range in [0..0, 0..PAGE - 1, 0..PAGE + 1, 1..PAGE + 1] {
        assert!(matches!(
            Placed::new(&mut pages.0[range], [1, 2]),
            Err(PlacementError::Geometry)
        ));
        pages.check(false);
    }
    assert!(matches!(
        Placed::new(pages.middle(), [0, 0]),
        Err(PlacementError::Identity)
    ));
    pages.check(true);
}
