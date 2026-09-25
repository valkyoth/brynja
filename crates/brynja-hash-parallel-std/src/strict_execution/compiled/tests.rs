pub(super) use super::super::tests::Point;
use super::*;
#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    Reorder,
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
            std::panic::resume_unwind(Box::new("strict ParallelHash fault"))
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
        Fault::Cancel(Point::Root),
        Fault::Revoke(Point::Root),
        Fault::Panic(Point::Root),
    ];
    if cfg!(any(miri, kani))
        || !cfg!(all(
            target_os = "linux",
            target_env = "gnu",
            target_pointer_width = "64",
            any(
                target_arch = "x86_64",
                all(target_arch = "aarch64", target_endian = "little")
            )
        ))
    {
        assert!(matches!(
            CompiledSession::new(
                Algorithm::ParallelHash128(256),
                Kernel::X86Keccak,
                LeafRoute::Single(Kernel::X86Keccak),
                limits()
            ),
            Err(Error::Resource(
                brynja_crypto_cpu_std::protected_memory::Error::Unsupported
            ))
        ));
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
            target_endian = "little",
            target_feature = "neon",
            target_feature = "sha3"
        )
    )
))]
mod native;
