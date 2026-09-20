//! Diagnostic observations, NOT an erasure acceptance gate.
use brynja_caller_residue_audit::PROBES;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod observer;

#[test]
fn public_calls_clear_only_the_owned_output_and_preserve_input() {
    for (_, probe, width) in PROBES {
        let input = [0x36; 256];
        for length in [0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 135, 136, 255, 256] {
            let mut output = [0xa5; 64];
            assert_eq!(probe(&input, &mut output, length), 0);
            assert_eq!(&output[..width], &vec![0; width]);
            assert_eq!(&output[width..], &vec![0xa5; 64 - width]);
            assert_eq!(input, [0x36; 256]);
        }
        let mut output = [0xa5; 64];
        assert_eq!(probe(&input, &mut output, 257), 2);
        assert_eq!(output, [0xa5; 64]);
    }
}

#[test]
fn public_implementations_match_known_abc_digests_before_output_drop() {
    macro_rules! known {
        ($state:path, $workspace:path, $hex:literal) => {{
            let expected = $hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let nibble = |byte| match byte {
                        b'0'..=b'9' => byte - b'0',
                        b'a'..=b'f' => byte - b'a' + 10,
                        _ => panic!("invalid test vector"),
                    };
                    nibble(pair[0]) * 16 + nibble(pair[1])
                })
                .collect::<Vec<_>>();
            let mut output = vec![0xa5; expected.len()];
            #[cfg(not(feature = "scoped"))]
            let mut state = <$state>::new();
            #[cfg(feature = "scoped")]
            let mut workspace = <$workspace>::new();
            #[cfg(feature = "scoped")]
            workspace.with(|mut state| {
                assert!(state.update(b"abc").is_ok());
                match state.finalize_secret(&mut output) {
                    Ok(secret) => assert_eq!(secret.expose(), expected),
                    Err(_) => panic!("valid synthetic scoped input rejected"),
                }
            });
            #[cfg(not(feature = "scoped"))]
            {
                assert!(state.update(b"abc").is_ok());
                match state.finalize_secret(&mut output) {
                    Ok(secret) => assert_eq!(secret.expose(), expected),
                    Err(_) => panic!("valid synthetic input rejected"),
                }
            }
            assert!(output.iter().all(|byte| *byte == 0));
        }};
    }
    known!(
        brynja_hash_sha2::HardenedSha256,
        brynja_hash_sha2::hardened_in_place::Sha256Workspace,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    known!(
        brynja_hash_sha2::HardenedSha512,
        brynja_hash_sha2::hardened_in_place::Sha512Workspace,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    known!(
        brynja_hash_sha3::HardenedSha3_256,
        brynja_hash_sha3::hardened_in_place::Sha3_256Workspace,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    known!(
        brynja_legacy_sha1::HardenedSha1,
        brynja_legacy_sha1::hardened_in_place::Sha1Workspace,
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    known!(
        brynja_legacy_md5::HardenedMd5,
        brynja_legacy_md5::hardened_in_place::Md5Workspace,
        "900150983cd24fb0d6963f7d28e17f72"
    );
}

#[test]
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn diagnostic_return_observations_are_not_cleanup_qualification() {
    println!(
        "\nCALLER_API_PROFILE: {}",
        brynja_caller_residue_audit::API_PROFILE
    );
    for (name, probe, width) in PROBES {
        let mut cases = 0;
        let mut input_marker_cases = 0;
        for marker in [0x36, 0xa7] {
            let input = [marker; 256];
            for length in [0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 135, 136, 255, 256] {
                let mut output = [0xa5; 64];
                let snapshot = observer::capture(probe, &input, &mut output, length);
                assert_eq!(snapshot[0], 0, "public probe rejected synthetic input");
                assert!(output[..width].iter().all(|byte| *byte == 0));
                assert!(output[width..].iter().all(|byte| *byte == 0xa5));
                assert_eq!(input, [marker; 256]);
                cases += 1;
                input_marker_cases += usize::from(observer::has_marker(&snapshot, marker));
            }
        }
        // No register values, addresses, digests, or input bytes are logged.
        println!(
            "\nCALLER_AUDIT: {name}; cases={cases}; input_marker_cases={input_marker_cases}; qualifies_cleanup=false"
        );
    }
}
