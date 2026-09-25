use super::worker::Boundary;
use super::*;
use brynja_legacy_sha1::hardened_execution::{Executor, in_place::Sha1Workspace};
#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    Cancel(Boundary),
    Revoke(Boundary),
    Panic(Boundary),
}
pub(super) fn inject(fault: Fault, point: Boundary, executor: &Executor, cancel: &Cancellation) {
    match fault {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Revoke(at) if at == point => executor.quarantine(),
        Fault::Panic(at) if at == point => {
            std::panic::resume_unwind(Box::new("strict SHA-1 fault"))
        }
        _ => (),
    }
}
pub(super) fn observe(
    scratch: &[u8],
    output: &[u8],
    executor: &Executor,
    workspace: &Sha1Workspace<'_>,
) {
    super::super::tests::configure(super::super::tests::Fault::VerifyStorage);
    super::super::tests::observe_storage(scratch);
    super::super::tests::observe_storage(output);
    super::super::tests::observe_storage(executor);
    super::super::tests::observe_storage(workspace);
}
fn limits() -> Limits {
    super::super::tests::limits()
}
#[test]
fn unsupported_target_model_or_missing_compiled_features_reject() {
    let _ = [
        Fault::Cancel(Boundary::Update),
        Fault::Revoke(Boundary::Setup),
        Fault::Panic(Boundary::Output),
    ];
    if let Err(error) = super::super::require_target() {
        assert!(matches!(CompiledSession::new(limits()), Err(found) if found == error));
    } else if !cfg!(any(
        all(
            target_arch = "x86_64",
            target_feature = "sha",
            target_feature = "sse2"
        ),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha2"
        )
    )) {
        assert!(matches!(
            CompiledSession::new(limits()),
            Err(Error::Execution(_))
        ));
    }
}
#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        all(
            target_arch = "x86_64",
            target_feature = "sha",
            target_feature = "sse2"
        ),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha2"
        )
    )
))]
mod native;
