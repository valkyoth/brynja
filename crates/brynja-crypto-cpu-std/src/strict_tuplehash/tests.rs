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
    WrongDeclaredLength,
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
fn limits() -> Limits {
    Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 65536,
        max_input_bits: 16000000,
        max_customization_bits: 8192,
        max_output_bits: 100000,
        max_items: 64,
        max_chunks: 128,
    }
}
pub(super) fn declared_bits(bits: u128) -> u128 {
    if matches!(FAULT.with(|f| f.get()), Fault::WrongDeclaredLength) {
        bits.saturating_add(1)
    } else {
        bits
    }
}
#[test]
fn metadata_bounds_and_unsupported_admission_are_fail_closed() {
    assert_eq!(
        Algorithm::TupleHash128(usize::MAX).output_bytes(),
        usize::MAX / 8 + 1
    );
    let mut bound = limits();
    bound.max_items = 0;
    bound.max_chunks = 0;
    assert_eq!(validate(bound, &[], &Bits::empty()), Ok(()));
    assert_eq!(
        validate(bound, &[Item::bytes(b"")], &Bits::empty()),
        Err(Error::WorkLimit)
    );
    bound = limits();
    bound.max_chunks = 1;
    let items = [Item {
        chunks: &[&[], &[]],
        tail: Bits::empty(),
    }];
    assert_eq!(
        validate(bound, &items, &Bits::empty()),
        Err(Error::WorkLimit)
    );
    bound = limits();
    bound.max_input_bits = 15;
    assert_eq!(
        validate(
            bound,
            &[Item::bytes(b"a"), Item::bytes(b"b")],
            &Bits::empty()
        ),
        Err(Error::WorkLimit)
    );
    bound = limits();
    bound.max_customization_bits = 7;
    assert_eq!(
        validate(bound, &[], &Bits::bytes(b"a")),
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
    if require_target().is_err() {
        assert!(matches!(
            Session::new(Algorithm::TupleHash256(256), limits()),
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
