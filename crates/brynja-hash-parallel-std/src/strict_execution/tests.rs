use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Point {
    Leaf(u128),
    Root,
    Output,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Fault {
    None,
    Reorder,
    Cancel(Point),
    Panic(Point),
}
pub(super) fn inject(fault: Fault, point: Point, cancel: &CancellationToken) {
    match fault {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Panic(at) if at == point => {
            std::panic::resume_unwind(Box::new("injected strict ParallelHash worker failure"))
        }
        _ => (),
    }
}
pub(super) fn observe<T: ?Sized>(value: &T) {
    #[cfg(all(target_os = "linux", target_env = "gnu", not(any(miri, kani))))]
    {
        if core::mem::size_of_val(value) == 0 {
            return;
        }
        let address = core::ptr::from_ref(value).cast::<u8>() as usize;
        let maps = std::fs::read_to_string("/proc/self/smaps").unwrap_or_default();
        let mut found = false;
        for line in maps.lines() {
            let first = line.split_whitespace().next().unwrap_or("");
            if let Some((low, high)) = first.split_once('-')
                && let (Ok(low), Ok(high)) = (
                    usize::from_str_radix(low, 16),
                    usize::from_str_radix(high, 16),
                )
            {
                found = low <= address && address < high;
            }
            if found && line.starts_with("VmFlags:") {
                for flag in ["lo", "dd", "dc"] {
                    assert!(line.split_whitespace().any(|v| v == flag), "{line}");
                }
                return;
            }
        }
        std::panic::resume_unwind(Box::new("strict storage lacks protected mapping"));
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu", not(any(miri, kani)))))]
    let _ = value;
}
pub(super) fn limits() -> Limits {
    Limits {
        workers: 3,
        max_leaves: 128,
        max_block_bytes: 4096,
        max_customization_bytes: 256,
        max_output_bits: 65536,
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 1048576,
    }
}
#[test]
fn shape_limits_fail_before_launch() {
    // Keep test-only fault identities compiled on rejecting/model targets too.
    let _ = [
        Fault::Reorder,
        Fault::Cancel(Point::Root),
        Fault::Panic(Point::Output),
    ];
    for workers in [0, 65, usize::MAX] {
        assert!(matches!(
            Session::new(
                Algorithm::ParallelHash128(256),
                Limits {
                    workers,
                    ..limits()
                }
            ),
            Err(Error::WorkLimit)
        ));
    }
    assert!(matches!(
        Session::new(Algorithm::ParallelHash128(usize::MAX), limits()),
        Err(Error::WorkLimit)
    ));
}
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
fn unsupported_never_falls_back() {
    assert!(matches!(
        Session::new(Algorithm::ParallelHash128(256), limits()),
        Err(Error::Resource(
            brynja_crypto_cpu_std::protected_memory::Error::Unsupported
        ))
    ));
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
pub(crate) mod native;
