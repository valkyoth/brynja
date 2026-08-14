//! Public runtime SHA-256 differential and dispatch tests.

use brynja_crypto_cpu_std::{RuntimeSha256Backend, RuntimeSha256Error, RuntimeSha256Selection};

const CASES: &[(&[u8], [u8; 32])] = &[
    (
        b"",
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ],
    ),
    (
        b"abc",
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ],
    ),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ],
    ),
];

#[test]
fn official_vectors_pass_through_runtime_selection() {
    let backend = RuntimeSha256Backend::opportunistic();
    for (input, expected) in CASES {
        let result = backend.hash(input);
        assert!(result.is_ok());
        let Ok(digest) = result else {
            continue;
        };
        assert_eq!(digest.as_bytes(), expected);
    }
}

#[test]
fn every_padding_boundary_and_partition_matches_scalar() {
    let backend = RuntimeSha256Backend::opportunistic();
    let mut content = [0_u8; 257];
    for (index, byte) in content.iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).unwrap_or(0);
    }
    for length in [0_usize, 1, 55, 56, 63, 64, 65, 127, 128, 129, 255, 256, 257] {
        let Some(input) = content.get(..length) else {
            continue;
        };
        let scalar = brynja_hash_sha2::sha256(input);
        assert!(scalar.is_ok());
        let Ok(scalar) = scalar else {
            continue;
        };
        assert_eq!(backend.hash(input), Ok(scalar));
        for width in 1..=80 {
            let mut state = backend.start();
            for chunk in input.chunks(width) {
                assert_eq!(state.update(chunk), Ok(()));
            }
            assert_eq!(state.finalize(), Ok(scalar));
        }
    }
}

#[test]
fn required_mode_is_explicit_and_report_matches_execution() {
    match RuntimeSha256Backend::required() {
        Ok(backend) => {
            let report = backend.report();
            assert_eq!(report.selection(), RuntimeSha256Selection::Accelerated);
            assert!(report.backend().is_some());
            assert!(report.backend_report().is_some());
            assert!(backend.hash(b"required backend").is_ok());
        }
        Err(error) => assert_eq!(error, RuntimeSha256Error::RequiredAccelerationUnavailable),
    }
}

#[test]
fn reusable_selection_has_no_cross_operation_state() {
    let backend = RuntimeSha256Backend::opportunistic();
    let first = backend.hash(b"first operation");
    let second = backend.hash(b"second operation");
    assert_eq!(
        first,
        brynja_hash_sha2::sha256(b"first operation").map_err(map_error)
    );
    assert_eq!(
        second,
        brynja_hash_sha2::sha256(b"second operation").map_err(map_error)
    );
}

fn map_error(_: brynja_hash_sha2::Sha256Error) -> RuntimeSha256Error {
    RuntimeSha256Error::MessageTooLong
}

#[cfg(brynja_cpu_evidence)]
#[test]
fn evidence_route_is_exact_and_accelerated() {
    let expected = std::env::var("BRYNJA_CPU_EVIDENCE_EXPECTED_BACKEND");
    assert!(expected.is_ok());
    let Ok(expected) = expected else {
        return;
    };
    let backend = RuntimeSha256Backend::required();
    assert!(backend.is_ok());
    let Ok(backend) = backend else {
        return;
    };
    let report = backend.report();
    assert_eq!(report.selection(), RuntimeSha256Selection::Accelerated);
    assert_eq!(
        report.backend().map(|value| value.as_str()),
        Some(expected.as_str())
    );
    assert!(report.backend_report().is_some());
    assert!(backend.hash(b"commit-bound native candidate route").is_ok());
}
