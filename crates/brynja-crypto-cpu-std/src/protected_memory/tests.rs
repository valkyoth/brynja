use super::{Error, ProtectedBytes, ProtectedStack, geometry::Layout};

#[test]
fn sizes_are_checked_before_any_allocation() -> Result<(), Error> {
    assert_eq!(Layout::new(0, usize::MAX, 4096), Err(Error::InvalidSize));
    for page in [0, 3, 4095, usize::MAX] {
        assert_eq!(Layout::new(1, usize::MAX, page), Err(Error::InvalidSize));
    }
    assert_eq!(
        Layout::new(usize::MAX, usize::MAX, 4096),
        Err(Error::InvalidSize)
    );
    assert_eq!(
        Layout::new(isize::MAX as usize, usize::MAX, 4096),
        Err(Error::InvalidSize)
    );
    for (bytes, payload, total) in [(1, 4096, 12288), (4096, 4096, 12288), (4097, 8192, 16384)] {
        let layout = Layout::new(bytes, total, 4096)?;
        assert_eq!(layout.payload, payload);
        assert_eq!(layout.total, total);
        assert_eq!(
            Layout::new(bytes, total.saturating_sub(1), 4096),
            Err(Error::ResourceLimit)
        );
    }
    Ok(())
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
fn unsupported_builds_never_mint_protected_storage() {
    let mut stacks: [ProtectedStack; 0] = [];
    let mut jobs: [fn(); 0] = [];
    assert_eq!(
        ProtectedStack::run_group(&mut stacks, &mut jobs),
        Err(Error::Unsupported)
    );
    for bytes in [0, 1, 4096, usize::MAX] {
        assert!(matches!(
            ProtectedBytes::new(bytes, usize::MAX),
            Err(Error::Unsupported)
        ));
        assert!(matches!(
            ProtectedStack::new(bytes, usize::MAX),
            Err(Error::Unsupported)
        ));
    }
}

#[test]
fn protected_owner_never_implicitly_formats_data() {
    let _resources = super::test_resource_guard();
    // Compile-fail doctests check the five forbidden traits. Keep a positive
    // type reference here so typos/removal cannot masquerade as their success.
    let _: fn(usize, usize) -> Result<ProtectedBytes, Error> = ProtectedBytes::new;
    let _: fn(usize, usize) -> Result<ProtectedStack, Error> = ProtectedStack::new;
}
