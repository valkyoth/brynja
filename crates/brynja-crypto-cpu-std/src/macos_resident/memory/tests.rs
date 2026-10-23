use super::*;

#[cfg(not(all(
    target_os = "macos",
    target_arch = "aarch64",
    target_pointer_width = "64",
    target_endian = "little",
    not(any(miri, kani))
)))]
#[test]
fn generic_resident_resources_reject_unsupported_targets() {
    assert!(matches!(
        ResidentBytes::new(32, 65536),
        Err(Error::Unsupported)
    ));
    assert!(matches!(
        ResidentStack::new(262144, 1048576),
        Err(Error::Unsupported)
    ));
}

#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    target_pointer_width = "64",
    target_endian = "little",
    not(any(miri, kani))
))]
#[test]
fn generic_resident_resources_validate_placement_clear_and_reuse() -> Result<(), Error> {
    assert!(matches!(
        ResidentStack::new(1, 1048576),
        Err(Error::InvalidSize)
    ));
    assert!(matches!(
        ResidentBytes::new(1, 1),
        Err(Error::ResourceLimit)
    ));
    let mut bytes = ResidentBytes::new(32, 65536)?;
    bytes.0.verify_native()?;
    bytes.as_bytes_mut().fill(0xa5);
    bytes.clear();
    assert!(bytes.as_bytes().iter().all(|b| *b == 0));
    let mut stack = ResidentStack::new(262144, 1048576)?;
    stack.0.verify_native()?;
    let start = stack.0.bytes().as_ptr() as usize;
    let end = start
        .checked_add(stack.0.bytes().len())
        .ok_or(Error::Invariant)?;
    let output = bytes.as_bytes_mut();
    stack.run(|| {
        let mut local = [0x51_u8; 128];
        let address = core::ptr::from_mut(&mut local) as usize;
        assert!(address >= start && address.checked_add(local.len()).is_some_and(|n| n <= end));
        output.copy_from_slice(local.get(..32).unwrap_or(&[]));
        core::hint::black_box(&mut local);
    })?;
    assert_eq!(bytes.as_bytes(), &[0x51; 32]);
    assert!(stack.0.bytes().iter().all(|b| *b == 0));
    assert_eq!(
        stack.run(|| std::panic::resume_unwind(Box::new("intentional resident resource unwind"))),
        Err(Error::WorkerPanicked)
    );
    assert!(stack.0.bytes().iter().all(|b| *b == 0));
    stack.run(|| {})?;
    stack.0.verify_native()?;
    bytes.clear();
    Ok(())
}
