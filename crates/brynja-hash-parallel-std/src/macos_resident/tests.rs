use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Point {
    Leaf(u128),
    Root,
    Output,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Fault {
    None,
    Reorder,
    Cancel(Point),
    Panic(Point),
}
pub(super) fn inject(fault: Fault, point: Point, cancel: &CancellationToken) {
    match fault {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Panic(at) if at == point => {
            std::panic::resume_unwind(Box::new("injected resident ParallelHash worker failure"))
        }
        _ => (),
    }
}
static RANGES: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());
pub(super) fn configure(session: &Session) {
    let mut ranges = RANGES.lock().unwrap_or_else(|p| p.into_inner());
    ranges.clear();
    for mapping in [
        &session.root,
        &session.cvs,
        &session.staging,
        &session.output,
    ]
    .into_iter()
    .chain(session.workers.iter())
    {
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani))))]
        assert_eq!(mapping.verify_native(), Ok(()));
        ranges.push((mapping.bytes().as_ptr() as usize, mapping.bytes().len()));
    }
}
pub(super) fn observe<T: ?Sized>(value: &T) {
    if core::mem::size_of_val(value) == 0 {
        return;
    }
    let address = core::ptr::from_ref(value).cast::<u8>() as usize;
    let size = core::mem::size_of_val(value);
    let ranges = RANGES.lock().unwrap_or_else(|p| p.into_inner());
    assert!(ranges.iter().any(|&(start, length)| {
        address >= start
            && address
                .checked_add(size)
                .is_some_and(|end| start.checked_add(length).is_some_and(|high| end <= high))
    }));
}
pub(super) fn limits() -> Limits {
    Limits {
        workers: 3,
        max_leaves: 128,
        max_block_bytes: 4096,
        max_customization_bytes: 256,
        max_output_bits: 65536,
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 1048576,
    }
}
#[test]
fn shape_limits_fail_before_launch() {
    // Keep test-only fault identities compiled on rejecting/model targets too.
    let _ = [
        Fault::Reorder,
        Fault::Cancel(Point::Root),
        Fault::Panic(Point::Output),
    ];
    for workers in [0, 65, usize::MAX] {
        assert!(matches!(
            Session::new(
                Algorithm::ParallelHash128(256),
                Limits {
                    workers,
                    ..limits()
                }
            ),
            Err(Error::WorkLimit)
        ));
    }
    assert!(matches!(
        Session::new(Algorithm::ParallelHash128(usize::MAX), limits()),
        Err(Error::WorkLimit)
    ));
}
#[cfg(not(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani)))))]
#[test]
fn unsupported_never_falls_back() {
    assert!(matches!(
        Session::new(Algorithm::ParallelHash128(256), limits()),
        Err(Error::Resource(ResourceError::Unsupported))
    ));
}
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani))))]
pub(crate) mod native;
