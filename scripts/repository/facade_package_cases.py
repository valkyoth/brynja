"""Public paths used by isolated consumers; no evidence-only API access."""

PROBES = {
    'cpu': 'cpu::Sha256Backend',
    'general-sha512-t': 'sha2::Sha512TBits',
    'sha2-static-execution': 'sha2::execution::StaticSelection',
    'sha2-runtime-execution': 'cpu::runtime_execution',
    'sha2-hardened-execution': 'sha2::hardened_execution::Execution',
    'sha256-batch': 'sha2::batch::Executor',
    'sha512-batch': 'sha2::batch512::Executor',
    'sha256-hardened-batch': 'sha2::hardened_batch::Executor',
    'sha512-hardened-batch': 'sha2::hardened_batch512::Executor',
    'sha3-static-execution': 'sha3::execution::StaticSelection',
    'sha3-runtime-execution': 'cpu::runtime_execution',
    'sha3-hardened-execution': 'sha3::hardened_execution::KeccakSession',
    'keccak-batch': 'sha3::batch::Executor',
    'keccak-hardened-batch': 'sha3::hardened_batch::Executor',
    'kmac-hardened-execution': 'kmac::execution::Kmac128',
    'kmac-runtime-execution': 'cpu::runtime_execution',
    'tuplehash-hardened-execution': 'tuplehash::execution::TupleHash128',
    'tuplehash-runtime-execution': 'cpu::runtime_execution',
    'parallelhash-hardened-execution': 'parallelhash::execution::Collector',
    'parallelhash-runtime-execution': 'cpu::runtime_execution',
    'parallelhash-hardened-batch': 'parallelhash::execution::batch',
}

PORTABLE = '''
#[test]
fn portable_namespaces_preserve_flat_apis() {
    assert_eq!(api::sha2::sha256(b"abc").unwrap(), api::sha256(b"abc").unwrap());
    assert_eq!(api::sha3::sha3_256(b"abc").unwrap(), api::sha3_256(b"abc").unwrap());
    let mut output = [0; 32];
    {
        let mut hash = api::sha2::HardenedSha256::new();
        hash.update(b"private input").unwrap();
        let secret = hash.finalize_secret(&mut output).unwrap();
        assert_eq!(secret.expose().len(), 32);
    }
    assert_eq!(output, [0; 32]);
}
'''

EXECUTION = '''
#[test]
fn ordinary_and_hardened_forwarding_preserve_results_and_cleanup() {
    use api::sha2::{execution as ordinary, hardened_execution as hardened};
    let reference = api::sha256(b"abc").unwrap();
    let result = ordinary::Sha256::hash(ordinary::Execution::portable(), b"abc").unwrap();
    assert_eq!(result.digest, reference);
    let mut stream = ordinary::Sha256::new(ordinary::Execution::portable()).unwrap();
    stream.update(b"a").unwrap();
    stream.update(b"bc").unwrap();
    assert_eq!(stream.finalize().unwrap().digest, reference);
    let mut output = [0; 32];
    {
        let result = hardened::Sha256::hash_secret(
            hardened::Execution::portable(), b"abc", &mut output).unwrap();
        assert_eq!(result.digest.expose(), reference.as_bytes());
    }
    assert_eq!(output, [0; 32]);
    let mut wrong = [0xa5; 31];
    assert!(hardened::Sha256::hash_secret(
        hardened::Execution::portable(), b"abc", &mut wrong).is_err());
    assert_eq!(wrong, [0; 31]);
}
'''

HOSTED = '''
#[test]
fn hosted_authority_is_separate_and_unavailability_is_explicit() {
    use host::execution::{Authority, Kernel, Mode, Route};
    use api::sha2::execution::{Execution, Sha256};
    // A deliberately wrong-architecture request never executes instructions.
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::X86Sha256
    } else {
        Kernel::ArmSha256
    };
    for mode in [Mode::Portable, Mode::Prefer] {
        let owner = Authority::new(kernel, mode).unwrap();
        assert!(matches!(owner.report().route,
            Route::PortableRequested | Route::PortableFallback(_)));
        let execution = match owner.session().unwrap() {
            Some(session) => Execution::from_runtime(session),
            None => Execution::portable(),
        };
        assert_eq!(Sha256::hash(execution, b"abc").unwrap().digest,
            api::sha256(b"abc").unwrap());
    }
    assert!(Authority::new(kernel, Mode::Require).is_err());
}
'''
