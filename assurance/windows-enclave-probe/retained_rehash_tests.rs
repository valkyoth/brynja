use brynja_hash_sha2::hardened_in_place::Sha256Workspace;
use core::mem::MaybeUninit;
use persistent_result::{Error, PUBLIC_OUTPUT};
use retained_placement::{PAGE, Placed};

#[repr(align(4096))]
struct Page([MaybeUninit<u8>; PAGE]);
fn cleared(page: &Page) {
    // Placement's complete page erase reinitializes padding before readback.
    for byte in &page.0 {
        assert_eq!(unsafe { byte.assume_init() }, 0);
    }
}
fn workspace_cleared(workspace: &Sha256Workspace) {
    // Builder binds initialized byte-array layout and size/alignment, no padding.
    let bytes =
        unsafe { core::slice::from_raw_parts(core::ptr::from_ref(workspace).cast::<u8>(), 1170) };
    assert!(
        bytes
            .iter()
            .all(|b| unsafe { core::ptr::read_volatile(b) } == 0)
    );
}
fn initial(owner: &mut Placed<'_>, message: &[u8]) -> [u64; 4] {
    let mut workspace = Sha256Workspace::new();
    let mut staging = [0xa5; 32];
    let token = owner.hash(&mut workspace, &mut staging, message).unwrap();
    workspace_cleared(&workspace);
    assert_eq!(staging, [0; 32]);
    token
}
fn rehash(owner: &mut Placed<'_>, token: [u64; 4]) -> Result<[u64; 4], Error> {
    let mut workspace = Sha256Workspace::new();
    let mut candidate = [0xa5; 32];
    let mut staging = [0xa5; 32];
    let result = owner.rehash(token, &mut workspace, &mut candidate, &mut staging);
    workspace_cleared(&workspace);
    assert_eq!(staging, [0; 32]);
    assert_eq!(candidate, [0; 32]);
    result
}
fn oracle(message: &[u8], chain: &[[u8; 32]; 4]) {
    for (depth, expected) in chain.iter().enumerate() {
        let mut page = Page([MaybeUninit::new(0xa5); PAGE]);
        let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
        let mut token = initial(&mut owner, message);
        for _ in 0..=depth {
            let next = rehash(&mut owner, token).unwrap();
            assert_eq!(next[2], token[2] + 1);
            token = next;
        }
        // All worker scratch has ceased to exist before explicit public export.
        owner
            .export_public(token, PUBLIC_OUTPUT, |bytes| {
                assert_eq!(bytes, expected);
                true
            })
            .unwrap();
        assert_eq!(owner.cancel(token), Err(Error::Spent));
        drop(owner);
        cleared(&page);
    }
}

#[test]
fn distinct_owner_and_stale_generation_rejections_do_not_export_secrets() {
    let mut first = Page([MaybeUninit::new(0xa5); PAGE]);
    let mut second = Page([MaybeUninit::new(0xa5); PAGE]);
    let mut a = Placed::new(&mut first.0, [7, 9]).unwrap();
    let mut b = Placed::new(&mut second.0, [8, 9]).unwrap();
    let token_a = initial(&mut a, b"abc");
    let token_b = initial(&mut b, b"abc");
    assert_eq!(rehash(&mut b, token_a), Err(Error::Rejected));
    assert_eq!(
        b.export_public(token_b, PUBLIC_OUTPUT, |_| panic!("cross owner")),
        Err(Error::Quarantined)
    );
    let next = rehash(&mut a, token_a).unwrap();
    assert_eq!(rehash(&mut a, token_a), Err(Error::Rejected));
    assert_eq!(
        a.export_public(next, PUBLIC_OUTPUT, |_| panic!("stale")),
        Err(Error::Quarantined)
    );
    drop(a);
    drop(b);
    cleared(&first);
    cleared(&second);
}

#[test]
fn cancelled_or_dropped_composed_result_is_cleared() {
    for cancel in [false, true] {
        let mut page = Page([MaybeUninit::new(0xa5); PAGE]);
        let mut owner = Placed::new(&mut page.0, [7, 9]).unwrap();
        let first = initial(&mut owner, b"abc");
        let next = rehash(&mut owner, first).unwrap();
        if cancel {
            owner.cancel(next).unwrap();
            assert_eq!(rehash(&mut owner, next), Err(Error::Spent));
        }
        drop(owner);
        cleared(&page);
    }
}
