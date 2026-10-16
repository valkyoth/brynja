use super::*;
type Ranges = [(usize, usize); 4];
thread_local! {
    static RANGES: std::cell::Cell<Ranges> = const { std::cell::Cell::new([(0, 0); 4]) };
}
pub(super) fn ranges(
    stack: &Mapping,
    staging: &Mapping,
    scratch: &Mapping,
    output: &Mapping,
) -> Ranges {
    [stack, staging, scratch, output].map(|mapping| {
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani))))]
        assert_eq!(mapping.verify_native(), Ok(()));
        (mapping.bytes().as_ptr() as usize, mapping.bytes().len())
    })
}
pub(super) fn configure(ranges: Ranges) {
    RANGES.with(|cell| cell.set(ranges));
}
pub(super) fn observe_staging(bytes: &[u8]) {
    RANGES.with(|cell| assert_eq!(cell.get()[1], (bytes.as_ptr() as usize, bytes.len())));
}
#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    Cancel(usize),
    Revoke(usize),
    Panic(usize),
}
pub(super) fn inject(fault: Fault, point: usize, revoke: impl FnOnce(), cancel: &Cancellation) {
    match fault {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Revoke(at) if at == point => revoke(),
        Fault::Panic(at) if at == point => {
            std::panic::resume_unwind(Box::new("resident batch fault"))
        }
        _ => (),
    }
}
pub(super) fn observe<W, A, E>(
    workspace: &W,
    authority: &A,
    executor: &E,
    output: &[u8],
    scratch: &[u8],
) {
    fn inside<T: ?Sized>(value: &T, index: usize) {
        let address = core::ptr::from_ref(value).cast::<u8>() as usize;
        let length = core::mem::size_of_val(value);
        RANGES.with(|cell| {
            let range = cell.get().get(index).copied();
            assert!(range.is_some());
            let Some((start, size)) = range else { return };
            assert!(
                address >= start
                    && address.checked_add(length).is_some_and(|end| start
                        .checked_add(size)
                        .is_some_and(|limit| end <= limit))
            );
        });
    }
    inside(workspace, 0);
    inside(authority, 0);
    inside(executor, 0);
    inside(scratch, 2);
    inside(output, 3);
}
fn limits() -> Limits {
    Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 1048576,
        max_input_bytes: 1_000_000,
        max_customization_bytes: 65536,
        max_output_bytes: 65536,
    }
}
#[test]
fn shapes_and_unsupported_platform_models_fail_closed() {
    let _ = [Fault::Cancel(0), Fault::Revoke(0), Fault::Panic(0)];
    let inputs = core::array::from_fn(|_| {
        Some(Input::bytes(
            Algorithm::Sha256(sha256::Algorithm::Sha256),
            b"abc",
        ))
    });
    assert!(validate(Route::Sha256(None), limits(), &inputs).is_ok());
    assert_eq!(
        validate(Route::Sha512(None), limits(), &inputs),
        Err(Error::InvalidInput)
    );
    let mut bound = limits();
    bound.max_output_bytes = 255;
    assert_eq!(
        validate(Route::Sha256(None), bound, &inputs),
        Err(Error::WorkLimit)
    );
    if super::super::require_native().is_err() {
        for route in [
            Route::Sha256(None),
            Route::Sha512(None),
            Route::Keccak(None),
            Route::Sha256(Some(Sha256Kernel::Neon)),
            Route::Sha512(Some(Sha512Kernel::Neon)),
            Route::Keccak(Some(KeccakKernel::Neon)),
        ] {
            assert!(matches!(
                Session::new(route, limits()),
                Err(Error::Resource(super::super::Error::Unsupported))
            ));
        }
    }
}
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani))))]
mod native;
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani))))]
mod sponge;
