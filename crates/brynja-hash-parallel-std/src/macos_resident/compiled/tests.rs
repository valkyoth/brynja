pub(super) use super::super::tests::Point;
use super::*;
#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    Reorder,
    NoVector,
    Cancel(Point),
    Revoke(Point),
    Panic(Point),
}
pub(super) fn inject(
    fault: Fault,
    point: Point,
    cancel: &CancellationToken,
    revoke: impl FnOnce(),
) {
    match fault {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Revoke(at) if at == point => revoke(),
        Fault::Panic(at) if at == point => {
            std::panic::resume_unwind(Box::new("resident ParallelHash fault"))
        }
        _ => (),
    }
}
#[test]
fn batch_cancellation_does_not_mask_backend_or_invariant_failure() {
    use brynja_hash_parallel::execution::batch;
    assert_eq!(
        worker::batch_error(batch::Error::Hash(batch::HashError::Cancelled)),
        Error::Cancelled
    );
    for error in [batch::HashError::Quarantined, batch::HashError::Invariant] {
        let error = batch::Error::Hash(error);
        assert_eq!(worker::batch_error(error), Error::Batch(error));
    }
}
pub(super) fn observe<A, W>(owner: &A, workspace: &W) {
    super::super::tests::observe(owner);
    super::super::tests::observe(workspace);
}
static VECTOR_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub(super) fn observe_batch(report: brynja_hash_parallel::execution::batch::KernelReport) {
    VECTOR_CALLS.fetch_add(report.vector_calls, std::sync::atomic::Ordering::Relaxed);
}
fn limits() -> Limits {
    super::super::tests::limits()
}
#[test]
fn unsupported_model_missing_bundle_wrong_operation_reject() {
    let _ = [
        Fault::Reorder,
        Fault::NoVector,
        Fault::Cancel(Point::Root),
        Fault::Revoke(Point::Root),
        Fault::Panic(Point::Root),
    ];
    if !cfg!(all(
        target_os = "macos",
        target_arch = "aarch64",
        not(any(miri, kani))
    )) {
        assert!(matches!(
            CompiledSession::new(
                Algorithm::ParallelHash128(256),
                Kernel::X86Keccak,
                LeafRoute::Single(Kernel::X86Keccak),
                limits()
            ),
            Err(Error::Resource(super::super::ResourceError::Unsupported))
        ));
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani))))]
    {
        use brynja_crypto_cpu::static_execution::Error as CpuError;
        for root in [Kernel::ArmSha256, Kernel::X86Sha256, Kernel::X86Keccak] {
            assert!(matches!(
                CompiledSession::new(
                    Algorithm::ParallelHash128(256),
                    root,
                    LeafRoute::Single(Kernel::ArmKeccak),
                    limits()
                ),
                Err(Error::Backend(
                    CpuError::WrongOperation | CpuError::WrongArchitecture
                ))
            ));
        }
        if !cfg!(target_feature = "sha3") {
            assert!(
                CompiledSession::new(
                    Algorithm::ParallelHash128(256),
                    Kernel::ArmKeccak,
                    LeafRoute::Single(Kernel::ArmKeccak),
                    limits()
                )
                .is_err()
            );
        } else {
            assert!(
                CompiledSession::new(
                    Algorithm::ParallelHash128(256),
                    Kernel::ArmKeccak,
                    LeafRoute::Batch(BatchKernel::Avx2),
                    limits()
                )
                .is_err()
            );
            assert!(
                CompiledSession::new(
                    Algorithm::ParallelHash128(256),
                    Kernel::ArmKeccak,
                    LeafRoute::Single(Kernel::ArmSha256),
                    limits()
                )
                .is_err()
            );
        }
    }
}
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    target_feature = "neon",
    target_feature = "sha3",
    not(any(miri, kani))
))]
mod native;
