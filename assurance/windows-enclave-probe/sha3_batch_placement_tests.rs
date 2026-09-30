//! Placement/lifetime checks only; native VBS admission is a separate campaign.
use super::*;

#[repr(align(4096))]
struct Page([u8; 4096]);
#[test]
fn placed_owner_is_destroyed_before_full_page_clear_and_can_be_recreated() {
    let mut page = std::boxed::Box::new(Page([0xa5; 4096]));
    let pointer = page.0.as_mut_ptr();
    // SAFETY: this test provides one aligned live exclusive page, uses only
    // constructor/destructor operations, and retains it until destruction.
    unsafe {
        assert_eq!(RetainedWork(0, pointer.add(1), 0x10000, 0x20000, 0), 200);
        assert_eq!(RetainedWork(0, pointer, 0x10000, 0x1ffff, 0), 200);
        assert_eq!(RetainedWork(0, pointer, 0x10000, 0x20000, 0), 1);
        assert_eq!(RetainedWork(0, pointer, 0x10000, 0x20000, 0), 201);
        let mut other = std::boxed::Box::new(Page([0x5a; 4096]));
        assert_eq!(
            RetainedWork(3, other.0.as_mut_ptr(), 0x10000, 0x20000, 0),
            203
        );
        assert_eq!(other.0, [0x5a; 4096]);
        // Retain a completed digest and a second live stream. Both and all
        // inactive allocation bytes must be cleared when the owner is destroyed.
        {
            let owner = &mut *pointer.cast::<Owner>();
            let mut plan = [sha3_batch::Slot::default(); 8];
            plan[0] = sha3_batch::Slot {
                identity: 2,
                width: 32,
                last: 8,
            };
            plan[1] = sha3_batch::Slot {
                identity: 8,
                width: 169,
                last: 3,
            };
            owner.begin(1, plan, 100).unwrap();
            owner.start(2, 0, 0, 0).unwrap();
            owner.finish_setup(3, 0).unwrap();
            owner.finish(4, 0, b"abc", 8).unwrap();
            owner.start(5, 1, 3, 0).unwrap();
            owner.setup_chunk(6, 1, true, &[5], 3).unwrap();
            owner.finish_setup(7, 1).unwrap();
            owner.update(8, 1, b"secret-prefix").unwrap();
        }
        assert_eq!(RetainedWork(3, pointer, 0x10000, 0x20000, 0), 4);
    }
    assert_eq!(page.0, [0; 4096]);
    let pointer = page.0.as_mut_ptr();
    // SAFETY: previous owner and all references ended before the page reborrow.
    unsafe {
        assert_eq!(RetainedWork(0, pointer, 0x10000, 0x20000, 0), 1);
        assert_eq!(RetainedWork(3, pointer, 0x10000, 0x20000, 0), 4);
        assert_eq!(RetainedWork(3, pointer, 0x10000, 0x20000, 0), 202);
    }
    assert_eq!(page.0, [0; 4096]);
}

// Placement tests never perform OS copying or callbacks. Any such attempt must
// fail, not masquerade as native execution.
#[unsafe(no_mangle)]
extern "C" fn PublicSha3BatchSource() -> usize {
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha3BatchInput(_: usize, _: *mut u8, _: usize, _: usize) -> i32 {
    -1
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha3BatchOutput(_: *const u8, _: usize) -> i32 {
    -1
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha3BatchObserve(_: usize, _: usize, _: usize) -> i32 {
    0
}
