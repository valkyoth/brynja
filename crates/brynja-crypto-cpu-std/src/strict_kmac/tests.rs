use super::*;

#[derive(Clone, Copy)]
#[cfg_attr(
    not(all(
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )),
    allow(dead_code)
)]
pub(super) enum Fault {
    None,
    VerifyStorage,
    CancelAt(usize),
    PanicAfterWrite(usize),
    VerifyCompared(usize),
}
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
    static COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static WRITES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
pub(super) fn configure(fault: Fault) {
    FAULT.with(|f| f.set(fault));
    COUNT.with(|c| c.set(0));
    WRITES.with(|c| c.set(0));
    COMPARED.with(|c| c.set(0));
}
pub(super) fn checkpoint(cancel: &Cancellation) {
    let count = COUNT.with(|c| {
        let old = c.get();
        c.set(old.saturating_add(1));
        old
    });
    if let Fault::CancelAt(wanted) = FAULT.with(|f| f.get())
        && count == wanted
    {
        cancel.cancel();
    }
}
pub(super) fn after_write() {
    let count = WRITES.with(|c| {
        let old = c.get();
        c.set(old.saturating_add(1));
        old
    });
    assert!(
        !matches!(FAULT.with(|f| f.get()), Fault::PanicAfterWrite(wanted) if wanted == count),
        "intentional strict sponge post-write unwind"
    );
}
pub(super) fn observe_storage<T: ?Sized>(value: &T) {
    if !matches!(FAULT.with(|f| f.get()), Fault::VerifyStorage) {
        return;
    }
    verify_mapping(value);
}
fn verify_mapping<T: ?Sized>(value: &T) {
    let address = core::ptr::from_ref(value).cast::<u8>() as usize;
    let maps = std::fs::read_to_string("/proc/self/smaps");
    assert!(maps.is_ok());
    if let Ok(maps) = maps {
        let mut selected = false;
        let mut verified = false;
        for line in maps.lines() {
            if let Some((range, _)) = line.split_once(' ')
                && let Some((start, stop)) = range.split_once('-')
                && let (Ok(start), Ok(stop)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(stop, 16),
                )
            {
                selected = start <= address && address < stop;
            }
            if selected && line.starts_with("VmFlags:") {
                for required in ["lo", "dd", "dc"] {
                    assert!(line.split_whitespace().any(|flag| flag == required));
                }
                verified = true;
            }
        }
        assert!(verified);
    }
}
pub(super) fn limits() -> Limits {
    Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 65536,
        max_message_bits: 16000000,
        max_setup_bits: 16384,
        max_output_bits: 100000,
        max_chunks: 128,
    }
}
pub(super) fn compared_byte() {
    COMPARED.with(|n| n.set(n.get().saturating_add(1)));
}
thread_local! { static COMPARED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
pub(super) fn comparison_complete() {
    if let Fault::VerifyCompared(wanted) = FAULT.with(|f| f.get()) {
        assert_eq!(COMPARED.with(|n| n.get()), wanted);
    }
}
#[cfg(feature = "strict-kmac-acceleration")]
pub(super) fn require_comparison_count(expected: usize) {
    assert_eq!(COMPARED.with(|n| n.get()), expected);
}
#[test]
fn metadata_and_model_admission_are_fail_closed() {
    let request = Request {
        key: Bits::bytes(&[1; 32]),
        customization: Bits::empty(),
        chunks: &[b"abc"],
        tail: Bits::empty(),
    };
    assert_eq!(
        validate(Algorithm::Kmac256(256), limits(), &request, None),
        Ok(())
    );
    assert_eq!(
        validate(
            Algorithm::Kmac256(256),
            limits(),
            &request,
            Some(&Bits::bytes(&[0; 31]))
        ),
        Err(Error::OutputLength)
    );
    assert_eq!(
        validate(
            Algorithm::KmacXof256(0),
            limits(),
            &request,
            Some(&Bits::empty())
        ),
        Err(Error::TagTooShort)
    );
    let mut bound = limits();
    bound.max_message_bits = 23;
    assert_eq!(
        validate(Algorithm::Kmac256(256), bound, &request, None),
        Err(Error::WorkLimit)
    );
    bound = limits();
    bound.max_setup_bits = 255;
    assert_eq!(
        validate(Algorithm::Kmac256(256), bound, &request, None),
        Err(Error::WorkLimit)
    );
    assert_eq!(
        bit_length(&Bits {
            bytes: &[],
            valid_bits: 8
        }),
        Err(Error::InvalidBits)
    );
    assert_eq!(
        bit_length(&Bits {
            bytes: &[255],
            valid_bits: 1
        }),
        Ok(1)
    );
    assert_eq!(
        Algorithm::KmacXof128(usize::MAX).output_bytes(),
        usize::MAX / 8 + 1
    );
    if require_target().is_err() {
        assert!(matches!(
            Session::new(Algorithm::Kmac256(256), limits()),
            Err(Error::Resource(crate::protected_memory::Error::Unsupported))
        ));
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
