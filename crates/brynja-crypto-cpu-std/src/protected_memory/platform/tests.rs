use super::super::{Error, ProtectedBytes};
use super::{Mapping, sys};
use sys::{
    Step,
    hooks::{self, Event},
};

#[test]
fn each_acquisition_failure_rolls_back_without_exposing_bytes() {
    let _resources = crate::protected_memory::test_resource_guard();
    for (step, error, calls) in [
        (Step::Map, Error::Mapping, vec![Step::Map]),
        (
            Step::Dump,
            Error::DumpExclusion,
            vec![Step::Map, Step::Dump, Step::Unmap],
        ),
        (
            Step::Fork,
            Error::ForkExclusion,
            vec![Step::Map, Step::Dump, Step::Fork, Step::Unmap],
        ),
        (
            Step::Access,
            Error::Access,
            vec![Step::Map, Step::Dump, Step::Fork, Step::Access, Step::Unmap],
        ),
        (
            Step::Lock,
            Error::Lock,
            vec![
                Step::Map,
                Step::Dump,
                Step::Fork,
                Step::Access,
                Step::Lock,
                Step::Unmap,
            ],
        ),
    ] {
        hooks::reset(Some(step));
        assert!(matches!(ProtectedBytes::new(1, 1 << 20), Err(actual) if actual == error));
        let expected: Vec<_> = calls.into_iter().map(Event::Call).collect();
        assert_eq!(hooks::events(), expected);
    }
    hooks::reset(None);
}

#[test]
fn native_mapping_is_guarded_resident_dump_excluded_and_not_inherited() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    hooks::reset(None);
    let mut mapping = Mapping::new(17, 1 << 20)?;
    assert_eq!(mapping.bytes(), &[0; 17]);
    mapping.bytes_mut().fill(0x95);
    let address = mapping.data.as_ptr() as usize;
    let maps = std::fs::read_to_string("/proc/self/smaps").map_err(|_| Error::Mapping)?;
    let mut selected = false;
    let mut vmflags = None;
    let mut locked = None;
    let mut guards = 0;
    for line in maps.lines() {
        if let Some((range, rest)) = line.split_once(' ')
            && let Some((start, end)) = range.split_once('-')
            && let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            )
        {
            selected = start <= address && address < end;
            if selected {
                assert_eq!(start, address);
                assert_eq!(end.checked_sub(start), Some(mapping.layout.payload));
                assert!(rest.starts_with("rw-p"));
            }
            if end == address || address.checked_add(mapping.layout.payload) == Some(start) {
                assert!(rest.starts_with("---p"));
                guards += 1;
            }
            continue;
        }
        if selected && line.starts_with("VmFlags:") {
            vmflags = Some(line.to_owned());
        }
        if selected && line.starts_with("Locked:") {
            locked = Some(line.to_owned());
        }
    }
    let flags = vmflags.ok_or(Error::Mapping)?;
    for flag in ["lo", "dd", "dc"] {
        assert!(
            flags.split_whitespace().any(|f| f == flag),
            "missing {flag}: {flags}"
        );
    }
    assert!(
        !flags.split_whitespace().any(|f| f == "lf"),
        "lazy locking is not eager residency"
    );
    let resident_kb = locked
        .ok_or(Error::Mapping)?
        .split_whitespace()
        .nth(1)
        .and_then(|word| word.parse::<usize>().ok())
        .ok_or(Error::Mapping)?;
    assert_eq!(resident_kb.checked_mul(1024), Some(mapping.layout.payload));
    assert_eq!(guards, 2);
    mapping.close()?;
    assert!(hooks::events().ends_with(&[Event::Clear(true), Event::Call(Step::Unmap)]));
    Ok(())
}

#[test]
fn explicit_release_failure_retains_cleared_locked_owner_for_retry() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    hooks::reset(None);
    let mut bytes = ProtectedBytes::new(31, 1 << 20)?;
    bytes.as_bytes_mut().fill(0xda);
    hooks::reset(Some(Step::Unmap));
    let Err((error, mut bytes)) = bytes.close() else {
        return Err(Error::Release);
    };
    assert_eq!(error, Error::Release);
    assert_eq!(bytes.as_bytes(), &[0; 31]);
    // Owner can still use the protected mapping; no premature successful close.
    bytes.as_bytes_mut().fill(0x7b);
    assert!(bytes.close().is_ok());
    assert_eq!(
        hooks::events(),
        vec![
            Event::Clear(true),
            Event::Call(Step::Unmap),
            Event::Clear(true),
            Event::Call(Step::Unmap)
        ]
    );
    Ok(())
}

#[test]
fn cleanup_covers_padding_and_runs_during_unwind() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    hooks::reset(None);
    let mut mapping = Mapping::new(1, 1 << 20)?;
    // Test-only expansion to dirty rounding padding, which the public API never
    // exposes. No resize/reallocation: used remains within the fixed payload.
    mapping.used = mapping.layout.payload;
    mapping.bytes_mut().fill(0xa5);
    mapping.used = 1;
    hooks::reset(None);
    let result = std::panic::catch_unwind(move || {
        let _mapping = mapping;
        assert!(
            std::hint::black_box(false),
            "intentional protected-resource unwind probe"
        );
    });
    assert!(result.is_err());
    assert_eq!(
        hooks::events(),
        vec![Event::Clear(true), Event::Call(Step::Unmap)]
    );
    Ok(())
}

#[test]
fn oversized_requests_do_not_call_the_os() {
    let _resources = crate::protected_memory::test_resource_guard();
    hooks::reset(None);
    assert!(matches!(
        ProtectedBytes::new(4096, 1),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        ProtectedBytes::new(usize::MAX, usize::MAX),
        Err(Error::InvalidSize)
    ));
    assert!(hooks::events().is_empty());
}

#[test]
#[ignore = "invoked in isolated child with zero residency limit by its parent test"]
fn zero_residency_limit_child() {
    let _resources = crate::protected_memory::test_resource_guard();
    assert!(matches!(
        ProtectedBytes::new(4096, 1 << 20),
        Err(Error::Lock)
    ));
}

#[test]
fn actual_zero_residency_limit_fails_closed_in_a_child() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let binary = std::env::current_exe().map_err(|_| Error::Mapping)?;
    let child = std::process::Command::new("bash")
        .args([
            "-c",
            "ulimit -l 0 || exit 97; exec \"$@\"",
            "protected-memory-limit",
        ])
        .arg(binary)
        .args([
            "--ignored",
            "--exact",
            "protected_memory::platform::tests::zero_residency_limit_child",
        ])
        .output()
        .map_err(|_| Error::Mapping)?;
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(String::from_utf8_lossy(&child.stdout).contains("1 passed"));
    Ok(())
}
