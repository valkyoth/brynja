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
        assert_eq!(RetainedWork(0, pointer, 0x10000, 0x20000, 0), 1);
        assert_eq!(RetainedWork(0, pointer, 0x10000, 0x20000, 0), 201);
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
extern "C" fn PublicSha2Source() -> usize {
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha2Input(_: usize, _: *mut u8, _: usize, _: usize) -> i32 {
    -1
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha2Output(_: *const u8, _: usize) -> i32 {
    -1
}
#[unsafe(no_mangle)]
extern "C" fn PublicSha2Observe(_: usize, _: usize, _: usize) -> i32 {
    0
}
