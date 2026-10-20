use super::*;

#[derive(Clone, Copy)]
#[allow(dead_code)] // Native injection variants cannot run on unsupported/model targets.
pub(super) enum Fault {
    None,
    Observe,
    Cancel(usize),
    Panic(usize),
    AfterWrite,
    #[cfg(feature = "strict-hmac-acceleration")]
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
        Fault::Panic(at) => assert_ne!(at, count, "intentional protected HMAC checkpoint unwind"),
        _ => {}
    }
}
pub(super) fn after_write() {
    assert!(
        !matches!(FAULT.with(|f| f.get()), Fault::AfterWrite),
        "intentional protected HMAC post-write unwind"
    );
}
#[cfg(feature = "strict-hmac-acceleration")]
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
    let address = core::ptr::from_ref(object).cast::<u8>() as usize;
    let end = address.checked_add(core::mem::size_of_val(object));
    assert!(end.is_some());
    let text = std::fs::read_to_string("/proc/self/smaps");
    assert!(text.is_ok());
    let mut selected = false;
    let mut verified = false;
    if let Ok(text) = text {
        for line in text.lines() {
            if let Some((range, _)) = line.split_once(' ')
                && let Some((start, stop)) = range.split_once('-')
                && let (Ok(start), Ok(stop)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(stop, 16),
                )
            {
                selected = start <= address && end.is_some_and(|end| end <= stop);
            }
            if selected && line.starts_with("VmFlags:") {
                for required in ["lo", "dd", "dc"] {
                    assert!(line.split_whitespace().any(|flag| flag == required));
                }
                verified = true;
            }
        }
    }
    assert!(verified);
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

#[cfg(not(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
)))]
#[test]
fn unsupported_platform_or_model_never_falls_back() {
    assert!(matches!(
        Session::<Sha256>::new(TagPolicy::Full, limits()),
        Err(Error::Resource(crate::protected_memory::Error::Unsupported))
    ));
}
