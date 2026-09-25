use super::*;
#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    Cancel(usize),
    Revoke(usize),
    Panic(usize),
}
pub(super) fn inject(fault: Fault, point: usize, revoke: impl FnOnce(), cancel: &Cancellation) {
    match fault {
        Fault::Cancel(at) if at == point => cancel.cancel(),
        Fault::Revoke(at) if at == point => revoke(),
        Fault::Panic(at) if at == point => {
            std::panic::resume_unwind(Box::new("strict batch fault"))
        }
        _ => (),
    }
}
pub(super) fn observe<W, A, E>(
    workspace: &W,
    authority: &A,
    executor: &E,
    output: &[u8],
    scratch: &[u8],
) {
    for address in [
        core::ptr::from_ref(workspace).cast::<u8>() as usize,
        core::ptr::from_ref(authority).cast::<u8>() as usize,
        core::ptr::from_ref(executor).cast::<u8>() as usize,
        output.as_ptr() as usize,
        scratch.as_ptr() as usize,
    ] {
        let maps = std::fs::read_to_string("/proc/self/smaps");
        assert!(maps.is_ok());
        if let Ok(maps) = maps {
            let (mut selected, mut found) = (false, false);
            for line in maps.lines() {
                if let Some((range, _)) = line.split_once(' ')
                    && let Some((a, b)) = range.split_once('-')
                    && let (Ok(a), Ok(b)) =
                        (usize::from_str_radix(a, 16), usize::from_str_radix(b, 16))
                {
                    selected = a <= address && address < b;
                }
                if selected && line.starts_with("VmFlags:") {
                    for flag in ["lo", "dd", "dc"] {
                        assert!(line.split_whitespace().any(|v| v == flag));
                    }
                    found = true;
                }
            }
            assert!(found);
        }
    }
}
fn limits() -> Limits {
    Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 1048576,
        max_input_bytes: 1_000_000,
        max_customization_bytes: 65536,
        max_output_bytes: 65536,
    }
}
#[test]
fn shapes_and_unsupported_platform_models_fail_closed() {
    let _ = [Fault::Cancel(0), Fault::Revoke(0), Fault::Panic(0)];
    let inputs = core::array::from_fn(|_| {
        Some(Input::bytes(
            Algorithm::Sha256(sha256::Algorithm::Sha256),
            b"abc",
        ))
    });
    assert!(validate(Route::Sha256(None), limits(), &inputs).is_ok());
    assert_eq!(
        validate(Route::Sha512(None), limits(), &inputs),
        Err(Error::InvalidInput)
    );
    let mut bound = limits();
    bound.max_output_bytes = 255;
    assert_eq!(
        validate(Route::Sha256(None), bound, &inputs),
        Err(Error::WorkLimit)
    );
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
            Session::new(Route::Sha256(None), limits()),
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
mod sponge;
