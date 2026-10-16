use super::worker::Boundary;
use super::*;
use brynja_crypto_cpu::static_execution::Authority;
#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    Cancel(Boundary),
    Revoke(Boundary),
    Panic(Boundary),
    CancelSecondOutput,
    RevokeSecondOutput,
    PanicSecondOutput,
}
thread_local! { static WRITES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
pub(super) fn inject(fault: Fault, point: Boundary, owner: &Authority, cancel: &Cancellation) {
    let second = point == Boundary::Output
        && WRITES.with(|c| {
            let count = c.get();
            c.set(count.saturating_add(1));
            count == 1
        });
    match fault {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Revoke(at) if at == point => owner.quarantine(),
        Fault::Panic(at) if at == point => {
            std::panic::resume_unwind(Box::new("strict sponge fault"))
        }
        Fault::CancelSecondOutput if second => cancel.cancel(),
        Fault::RevokeSecondOutput if second => owner.quarantine(),
        Fault::PanicSecondOutput if second => {
            std::panic::resume_unwind(Box::new("strict XOF fault"))
        }
        _ => (),
    }
}
pub(super) fn observe(
    scratch: &[u8],
    output: &[u8],
    owner: &Authority,
    session: &brynja_hash_sha3::hardened_execution::KeccakSession<'_>,
) {
    WRITES.with(|c| c.set(0));
    super::super::tests::observe_storage(scratch);
    OUTPUT.with(|range| assert_eq!((output.as_ptr() as usize, output.len()), range.get()));
    super::super::tests::observe_storage(owner);
    super::super::tests::observe_storage(session);
}
pub(super) fn observe_workspace<T>(workspace: &T) {
    super::super::tests::observe_storage(workspace);
}
fn limits() -> Limits {
    super::super::tests::limits()
}
#[test]
fn wrong_operation_missing_features_and_unsupported_models_reject() {
    // Keep test hooks type-checked even when native tests are excluded.
    let _ = [
        Fault::Cancel(Boundary::Prefix),
        Fault::Revoke(Boundary::Update),
        Fault::Panic(Boundary::Finalize),
        Fault::CancelSecondOutput,
        Fault::RevokeSecondOutput,
        Fault::PanicSecondOutput,
    ];
    for kernel in [
        Kernel::X86Sha256,
        Kernel::X86Sha512,
        Kernel::ArmSha256,
        Kernel::ArmSha512,
    ] {
        assert_eq!(
            compatible(kernel),
            Err(Error::Backend(
                brynja_crypto_cpu::static_execution::Error::WrongOperation
            ))
        );
    }
    for kernel in [Kernel::X86Keccak, Kernel::ArmKeccak] {
        if let Err(error) = require_target() {
            assert!(
                matches!(CompiledSession::new(Algorithm::Sha3_256, kernel, limits()), Err(found) if found == error)
            );
        } else if compatible(kernel).is_ok()
            && let Err(error) = kernel.check_compiled_target()
        {
            assert!(
                matches!(CompiledSession::new(Algorithm::Sha3_256, kernel, limits()), Err(Error::Backend(found)) if found == error)
            );
        }
    }
}
thread_local! { static OUTPUT: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) }; }
pub(super) fn configure(range: (usize, usize), output: (usize, usize)) {
    OUTPUT.with(|r| r.set(output));
    super::super::tests::configure(super::super::tests::Fault::VerifyStorage, range);
}
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    target_endian = "little",
    target_pointer_width = "64",
    not(any(miri, kani))
))]
mod native;

#[test]
fn x86_routes_are_not_mac_resident_routes() {
    assert!(compatible(Kernel::X86Keccak).is_err());
}
