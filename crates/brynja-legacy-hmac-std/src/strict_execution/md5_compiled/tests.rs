use super::*;
use brynja_legacy_hmac::md5_batch::{Md5Executor, Report};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(super) enum Fault {
    None,
    Observe,
    Cancel(usize),
    Revoke(usize),
    Panic(usize),
    WrongReport,
    WrongShape,
}
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
    static COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
pub(super) static OBSERVED: AtomicUsize = AtomicUsize::new(0);
pub(super) fn configure(fault: Fault) {
    FAULT.with(|f| f.set(fault));
    COUNT.with(|c| c.set(0));
    OBSERVED.store(0, Ordering::SeqCst);
}
pub(super) fn checkpoint(owner: &Md5Executor, cancel: &Cancellation) {
    let point = COUNT.with(|c| {
        let n = c.get();
        c.set(n.saturating_add(1));
        n
    });
    OBSERVED.store(point.saturating_add(1), Ordering::SeqCst);
    match FAULT.with(|f| f.get()) {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Revoke(at) if at == point => {
            owner.quarantine();
            cancel.cancel();
        }
        Fault::Panic(at) => assert_ne!(at, point, "intentional hosted MD5 unwind"),
        _ => (),
    }
}
pub(super) fn after_write(owner: &Md5Executor, cancel: &Cancellation) {
    checkpoint(owner, cancel);
}
pub(super) fn report(mut value: Report) -> Report {
    if matches!(FAULT.with(|f| f.get()), Fault::WrongReport) {
        value.inner.vector_blocks = 0;
    }
    value
}
pub(super) fn result(value: &mut Result<Option<bool>, Error>) {
    if matches!(FAULT.with(|f| f.get()), Fault::WrongShape) {
        *value = match value {
            Ok(Some(_)) => Ok(None),
            _ => Ok(Some(false)),
        };
    }
}
pub(super) fn observe<T>(state: &T, staging: &[u8], output: &[u8]) {
    if matches!(FAULT.with(|f| f.get()), Fault::Observe) {
        super::super::tests::configure(super::super::tests::Fault::Observe);
        super::super::tests::observe(state, staging, output);
    }
}
fn limits() -> Md5BatchLimits {
    Md5BatchLimits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 65536,
        max_key_bytes: 8192,
        max_message_bits: 200000,
        max_compressions: 20000,
    }
}
#[test]
fn batch_metadata_and_public_admission() {
    for bytes in 10..=16 {
        assert_eq!(TagPolicy::Bytes(bytes).bytes::<Md5>(), Ok(bytes));
    }
    for width in [4, 8] {
        let inputs = core::array::from_fn(|_| {
            Some(Md5BatchInput {
                key: b"key",
                message: Bits {
                    bytes: &[255],
                    valid_bits: 3,
                },
            })
        });
        assert_eq!(types::validate(&inputs, None, limits(), width, 16), Ok(())); // No secret content inspection.
        assert_eq!(
            types::validate(&inputs, Some(&[Some(&[0; 15]); 8]), limits(), width, 16),
            Err(Error::OutputLength)
        );
        let mut bound = limits();
        bound.max_key_bytes = 2;
        assert_eq!(
            types::validate(&inputs, None, bound, width, 16),
            Err(Error::WorkLimit)
        );
        bound = limits();
        bound.max_message_bits = 2;
        assert_eq!(
            types::validate(&inputs, None, bound, width, 16),
            Err(Error::WorkLimit)
        );
    }
    let half: [Option<Md5BatchInput<'_>>; 8] = core::array::from_fn(|lane| {
        (lane < 4).then_some(Md5BatchInput {
            key: b"key",
            message: Bits::empty(),
        })
    });
    assert_eq!(
        types::validate(&half, Some(&[Some(&[0; 16]); 8]), limits(), 4, 16),
        Err(Error::OutputLength)
    );
    let candidates =
        core::array::from_fn(|lane| if lane < 4 { Some(&[0u8; 16][..]) } else { None });
    assert_eq!(
        types::validate(&half, Some(&candidates), limits(), 4, 16),
        Ok(())
    );
    assert_eq!(
        types::validate(&[const { None }; 8], None, limits(), 0, 16),
        Err(Error::Invariant)
    );
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
            target_feature = "neon"
        )
    )
))]
mod native;
#[cfg(not(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(
            target_arch = "aarch64",
            target_endian = "little",
            target_feature = "neon"
        )
    )
)))]
#[test]
fn missing_native_simd_or_platform_never_falls_back() {
    assert!(matches!(
        Md5BatchSession::new(LegacyUse::acknowledge(), TagPolicy::Full, limits()),
        Err(Error::Resource(protected_memory::Error::Unsupported))
            | Err(Error::Mac(brynja_legacy_hmac::Error::ExecutionUnavailable))
    ));
}
