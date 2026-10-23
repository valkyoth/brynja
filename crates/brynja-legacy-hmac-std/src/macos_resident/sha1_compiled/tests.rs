use super::*;
use brynja_legacy_hmac::execution::Sha1Executor;

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(super) enum Fault {
    None,
    Revoke(usize),
    WrongShape,
}
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
    static COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
pub(super) fn configure(fault: Fault) {
    FAULT.with(|f| f.set(fault));
    COUNT.with(|c| c.set(0));
}
pub(super) fn checkpoint(owner: &Sha1Executor) {
    let point = COUNT.with(|c| {
        let n = c.get();
        c.set(n.saturating_add(1));
        n
    });
    if matches!(FAULT.with(|f| f.get()), Fault::Revoke(at) if at == point) {
        owner.quarantine();
    }
}
pub(super) fn result(value: &mut Result<Option<bool>, Error>) {
    if matches!(FAULT.with(|f| f.get()), Fault::WrongShape) {
        *value = match value {
            Ok(Some(_)) => Ok(None),
            _ => Ok(Some(false)),
        };
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
fn only_pre_entry_thread_errors_are_reusable() {
    assert!(pre_entry(macos_resident::Error::ThreadStart));
    assert!(pre_entry(macos_resident::Error::ThreadAttributes));
    assert!(!pre_entry(macos_resident::Error::Unsupported));
    assert!(!pre_entry(macos_resident::Error::WorkerPanicked));
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    not(any(miri, kani)),
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    target_feature = "sha2"
))]
mod native;

#[cfg(not(all(
    target_os = "macos",
    target_pointer_width = "64",
    not(any(miri, kani)),
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    target_feature = "sha2"
)))]
#[test]
fn missing_native_platform_or_features_never_falls_back() {
    let result = Sha1CompiledSession::new(LegacyUse::acknowledge(), TagPolicy::Full, limits());
    assert!(matches!(
        result,
        Err(Error::Resource(macos_resident::Error::Unsupported))
            | Err(Error::Mac(brynja_legacy_hmac::Error::ExecutionUnavailable))
    ));
}
