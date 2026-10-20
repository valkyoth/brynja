use super::*;

#[derive(Clone, Copy)]
#[allow(dead_code)] // Native injection variants cannot run on unsupported/model targets.
pub(super) enum Fault {
    None,
    Observe,
    Cancel(usize),
    Panic(usize),
    AfterWrite,
    #[cfg(feature = "macos-resident-hmac-acceleration")]
    Revoke(usize),
}
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
    static COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
pub(super) fn configure(fault: Fault) {
    FAULT.with(|f| f.set(fault));
    COUNT.with(|c| c.set(0));
}
pub(super) fn checkpoint(cancel: &Cancellation) {
    let count = COUNT.with(|c| {
        let old = c.get();
        c.set(old.saturating_add(1));
        old
    });
    match FAULT.with(|f| f.get()) {
        Fault::Cancel(at) if at == count => cancel.cancel(),
        Fault::Panic(at) => assert_ne!(at, count, "intentional resident HMAC checkpoint unwind"),
        _ => {}
    }
}
pub(super) fn after_write() {
    assert!(
        !matches!(FAULT.with(|f| f.get()), Fault::AfterWrite),
        "intentional resident HMAC post-write unwind"
    );
}
#[cfg(feature = "macos-resident-hmac-acceleration")]
pub(super) fn revoke(owner: &brynja_crypto_cpu::static_execution::Authority) {
    let point = COUNT.with(|c| c.get().saturating_sub(1));
    if matches!(FAULT.with(|f| f.get()), Fault::Revoke(at) if at == point) {
        owner.quarantine();
    }
}
pub(super) fn observe<T>(state: &T, staging: &[u8], output: &[u8]) {
    if !matches!(FAULT.with(|f| f.get()), Fault::Observe) {
        return;
    }
    mapping(state);
    mapping(staging);
    mapping(output);
}
fn mapping<T: ?Sized>(object: &T) {
    super::super::test_storage::observe(object);
}
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani))))]
pub(super) fn resources() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani))))]
pub(super) fn verify_resources<A: Algorithm>(s: &Session<A>) -> Result<(), Error> {
    s.stack.verify_native()?;
    s.staging.verify_native()?;
    s.output.verify_native()?;
    Ok(())
}
pub(super) fn limits() -> Limits {
    Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 65536,
        max_key_bytes: 8192,
        max_message_bits: 200000,
        max_chunks: 16,
    }
}

#[test]
fn metadata_admission_and_exact_tag_policy() {
    assert_eq!(TagPolicy::Full.bits::<Sha512T<129>>(), Ok(129));
    assert_eq!(TagPolicy::Bytes(16).bits::<Sha512T<129>>(), Ok(128));
    for policy in [
        TagPolicy::Bytes(0),
        TagPolicy::Bytes(15),
        TagPolicy::Bytes(17),
        TagPolicy::Bytes(usize::MAX),
    ] {
        assert_eq!(policy.bits::<Sha512T<129>>(), Err(Error::InvalidTagPolicy));
    }
    for result in [
        TagPolicy::Full.bits::<Sha512T<0>>(),
        TagPolicy::Full.bits::<Sha512T<127>>(),
        TagPolicy::Full.bits::<Sha512T<384>>(),
        TagPolicy::Full.bits::<Sha512T<512>>(),
    ] {
        assert_eq!(
            result,
            Err(Error::Mac(brynja_mac_hmac::Error::AlgorithmParameter))
        );
    }
    let request = Request {
        key: b"key",
        chunks: &[b"abc"],
        tail: Bits {
            bytes: &[255],
            valid_bits: 3,
        },
    };
    // Host validation is deliberately length-only, not secret-content parsing.
    assert_eq!(types::validate(limits(), &request, None, 32), Ok(()));
    let mut bound = limits();
    bound.max_message_bits = 26;
    assert_eq!(
        types::validate(bound, &request, None, 32),
        Err(Error::WorkLimit)
    );
    bound.max_message_bits = 27;
    assert_eq!(types::validate(bound, &request, None, 32), Ok(()));
    bound.max_key_bytes = 2;
    assert_eq!(
        types::validate(bound, &request, None, 32),
        Err(Error::WorkLimit)
    );
    assert_eq!(
        types::validate(limits(), &request, Some(&[0; 31]), 32),
        Err(Error::OutputLength)
    );
    assert_eq!(
        Bits {
            bytes: &[],
            valid_bits: 8
        }
        .bit_len(),
        Err(Error::InvalidBits)
    );
    assert_eq!(
        Bits {
            bytes: &[1],
            valid_bits: 0
        }
        .bit_len(),
        Err(Error::InvalidBits)
    );
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    not(any(miri, kani)),
    target_arch = "aarch64",
    target_endian = "little"
))]
mod native;

#[cfg(not(all(
    target_os = "macos",
    target_pointer_width = "64",
    not(any(miri, kani)),
    target_arch = "aarch64",
    target_endian = "little"
)))]
#[test]
fn unsupported_platform_or_model_never_falls_back() {
    assert!(matches!(
        Session::<Sha256>::new(TagPolicy::Full, limits()),
        Err(Error::Resource(crate::macos_resident::Error::Unsupported))
    ));
}
