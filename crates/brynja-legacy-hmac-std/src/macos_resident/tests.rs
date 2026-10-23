use super::*;

#[derive(Clone, Copy)]
#[allow(dead_code)] // Native injections are not executed on unsupported/model targets.
pub(super) enum Fault {
    None,
    Cancel(usize),
    Panic(usize),
    AfterWriteCancel,
    AfterWritePanic,
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
    let point = COUNT.with(|c| {
        let p = c.get();
        c.set(p.saturating_add(1));
        p
    });
    match FAULT.with(|f| f.get()) {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Panic(at) => assert_ne!(at, point, "intentional legacy HMAC worker unwind"),
        _ => {}
    }
}
pub(super) fn after_write(cancel: &Cancellation) {
    match FAULT.with(|f| f.get()) {
        Fault::AfterWriteCancel => cancel.cancel(),
        fault => assert!(
            !matches!(fault, Fault::AfterWritePanic),
            "intentional post-write unwind"
        ),
    }
}
fn limits() -> Limits {
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
fn metadata_and_preselected_tag_policy() {
    assert_eq!(TagPolicy::Full.bytes::<Sha1>(), Ok(20));
    assert_eq!(TagPolicy::Full.bytes::<Md5>(), Ok(16));
    for bytes in 10..=20 {
        assert_eq!(TagPolicy::Bytes(bytes).bytes::<Sha1>(), Ok(bytes));
        if bytes <= 16 {
            assert_eq!(TagPolicy::Bytes(bytes).bytes::<Md5>(), Ok(bytes));
        } else {
            assert_eq!(
                TagPolicy::Bytes(bytes).bytes::<Md5>(),
                Err(Error::InvalidTagPolicy)
            );
        }
    }
    for bytes in [0, 1, 9, 21, usize::MAX] {
        assert_eq!(
            TagPolicy::Bytes(bytes).bytes::<Sha1>(),
            Err(Error::InvalidTagPolicy)
        );
        assert_eq!(
            TagPolicy::Bytes(bytes).bytes::<Md5>(),
            Err(Error::InvalidTagPolicy)
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
    // Content is intentionally not read by host admission.
    assert_eq!(types::validate(limits(), &request, None, 20), Ok(()));
    let mut bound = limits();
    bound.max_message_bits = 26;
    assert_eq!(
        types::validate(bound, &request, None, 20),
        Err(Error::WorkLimit)
    );
    bound.max_message_bits = 27;
    assert_eq!(types::validate(bound, &request, None, 20), Ok(()));
    bound.max_key_bytes = 2;
    assert_eq!(
        types::validate(bound, &request, None, 20),
        Err(Error::WorkLimit)
    );
    assert_eq!(
        types::validate(limits(), &request, Some(&[0; 19]), 20),
        Err(Error::OutputLength)
    );
    for tail in [
        Bits {
            bytes: &[],
            valid_bits: 1,
        },
        Bits {
            bytes: &[1],
            valid_bits: 0,
        },
        Bits {
            bytes: &[1],
            valid_bits: 9,
        },
    ] {
        assert_eq!(
            types::validate(
                limits(),
                &Request {
                    key: &[],
                    chunks: &[],
                    tail
                },
                None,
                20
            ),
            Err(Error::InvalidBits)
        );
    }
    let mut bound = limits();
    bound.max_chunks = 0;
    assert!(matches!(
        Session::<Sha1>::new(LegacyUse::acknowledge(), TagPolicy::Full, bound),
        Err(Error::InvalidLimits)
    ));
}

#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    target_pointer_width = "64",
    target_endian = "little",
    not(any(miri, kani))
))]
mod native;

#[cfg(not(all(
    target_os = "macos",
    target_arch = "aarch64",
    target_pointer_width = "64",
    target_endian = "little",
    not(any(miri, kani))
)))]
#[test]
fn unsupported_target_or_model_never_falls_back() {
    assert!(matches!(
        Session::<Sha1>::new(LegacyUse::acknowledge(), TagPolicy::Full, limits()),
        Err(Error::Resource(
            brynja_crypto_cpu_std::macos_resident::Error::Unsupported
        ))
    ));
}
