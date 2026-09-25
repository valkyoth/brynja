use super::*;
use brynja_crypto_cpu::static_execution::Authority;
use std::sync::atomic::{AtomicU64, Ordering};
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Point {
    Update,
    Finalize,
    Output,
}
#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    Cancel(Point),
    Revoke(Point),
    Panic(Point),
}
pub(super) fn inject(fault: Fault, point: Point, owner: &Authority, cancel: &Cancellation) {
    match fault {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Revoke(at) if at == point => owner.quarantine(),
        Fault::Panic(at) if at == point => {
            std::panic::resume_unwind(Box::new("strict compiled worker fault"))
        }
        _ => (),
    }
}
pub(super) fn observe(staged: &[u8], output: &[u8], owner: &Authority) {
    super::super::tests::configure(super::super::tests::Fault::VerifyStorage);
    super::super::tests::observe_storage(staged);
    super::super::tests::observe_storage(output);
    super::super::tests::observe_storage(owner);
}
pub(super) fn observe_workspace<T>(workspace: &T) {
    super::super::tests::observe_storage(workspace);
}
static LAST_MESSAGE_BLOCKS: AtomicU64 = AtomicU64::new(0);
pub(super) fn record(report: brynja_hash_sha2::execution::Report) {
    LAST_MESSAGE_BLOCKS.store(
        u64::try_from(report.message_blocks).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}
fn limits() -> Limits {
    super::super::tests::limits()
}
#[test]
fn identity_compatibility_rejects_keccak_and_wrong_width() {
    let _ = [
        Fault::Cancel(Point::Update),
        Fault::Revoke(Point::Finalize),
        Fault::Panic(Point::Output),
    ];
    for (algorithm, kernel) in [
        (Algorithm::Sha256, Kernel::X86Sha512),
        (Algorithm::Sha512, Kernel::ArmSha256),
        (Algorithm::Sha256, Kernel::X86Keccak),
        (Algorithm::Sha512, Kernel::ArmKeccak),
    ] {
        assert_eq!(
            compatible(algorithm, kernel),
            Err(Error::Backend(
                brynja_crypto_cpu::static_execution::Error::WrongOperation
            ))
        );
    }
}
#[test]
fn missing_static_features_and_unsupported_platforms_never_fall_back() {
    let _resources = crate::protected_memory::test_resource_guard();
    for kernel in [
        Kernel::X86Sha256,
        Kernel::X86Sha512,
        Kernel::ArmSha256,
        Kernel::ArmSha512,
    ] {
        let algorithm = if matches!(kernel, Kernel::X86Sha256 | Kernel::ArmSha256) {
            Algorithm::Sha256
        } else {
            Algorithm::Sha512
        };
        if let Err(error) = require_target() {
            assert!(
                matches!(CompiledSession::new(algorithm, kernel, limits()), Err(found) if found == error)
            );
        } else if let Err(error) = kernel.check_compiled_target() {
            assert!(
                matches!(CompiledSession::new(algorithm, kernel, limits()), Err(Error::Backend(found)) if found == error)
            );
        }
    }
}
#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
mod native;
