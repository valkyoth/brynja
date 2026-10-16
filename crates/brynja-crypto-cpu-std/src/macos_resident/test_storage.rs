//! Test-only address provenance, independently of source-level placement claims.
use super::resource::Mapping;
type Ranges = [(usize, usize); 3];
thread_local! {
    static RANGES: std::cell::Cell<Ranges> = const { std::cell::Cell::new([(0, 0); 3]) };
}
pub(super) fn ranges_for_worker(stack: &Mapping, staging: &[u8], output: &[u8]) -> Ranges {
    [stack.bytes(), staging, output].map(|bytes| (bytes.as_ptr() as usize, bytes.len()))
}
pub(super) fn configure(ranges: Ranges) {
    RANGES.with(|cell| cell.set(ranges));
}
pub(super) fn observe<T: ?Sized>(value: &T) {
    let address = core::ptr::from_ref(value).cast::<u8>() as usize;
    let length = core::mem::size_of_val(value);
    assert!(RANGES.with(|cell| cell.get().iter().any(|&(start, size)| {
        address >= start
            && address
                .checked_add(length)
                .is_some_and(|end| start.checked_add(size).is_some_and(|limit| end <= limit))
    })));
}
