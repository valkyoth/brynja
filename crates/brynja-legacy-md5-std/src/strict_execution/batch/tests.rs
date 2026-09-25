use super::*;
#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    Cancel(usize),
    Revoke(usize),
    Panic(usize),
}
pub(super) fn inject(fault: Fault, point: usize, executor: &api::Executor, cancel: &Cancellation) {
    match fault {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Revoke(at) if at == point => executor.quarantine(),
        Fault::Panic(at) if at == point => {
            std::panic::resume_unwind(Box::new("strict MD5 batch fault"))
        }
        _ => (),
    }
}
pub(super) fn observe(
    workspace: &api::in_place::Workspace<'_>,
    executor: &api::Executor,
    staging: &[[u8; 16]; 8],
    destination: &[u8],
) {
    super::super::tests::configure(super::super::tests::Fault::VerifyStorage);
    super::super::tests::observe_storage(workspace);
    super::super::tests::observe_storage(executor);
    super::super::tests::observe_storage(staging);
    super::super::tests::observe_storage(destination);
}
fn limits() -> Limits {
    Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_output_mapping_bytes: 65536,
        max_input_bits: 16000000,
    }
}
#[test]
fn admission_and_public_request_bounds_fail_closed() {
    let _ = [Fault::Cancel(0), Fault::Revoke(0), Fault::Panic(0)];
    assert_eq!(validate(&core::array::from_fn(|_| None), 0), Ok(()));
    assert_eq!(
        validate(&core::array::from_fn(|_| Some(Input::bytes(b"a"))), 63),
        Err(Error::WorkLimit)
    );
    assert_eq!(
        validate(
            &core::array::from_fn(|_| Some(Input {
                bytes: &[],
                valid_bits: 8
            })),
            64
        ),
        Err(Error::InvalidBits)
    );
    if super::super::require_target().is_err() {
        assert!(matches!(
            Session::new(limits()),
            Err(Error::Resource(protected_memory::Error::Unsupported))
        ));
    } else if !cfg!(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    )) {
        assert!(matches!(Session::new(limits()), Err(Error::Execution(_))));
    }
}
#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_endian = "little"
        )
    )
))]
mod native;
