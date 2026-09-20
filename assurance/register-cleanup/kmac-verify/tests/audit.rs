use brynja_kmac_verify_caller::{EXPECTED, PROBES};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "../../caller-audit/tests/observer/mod.rs"]
mod observer;

#[test]
fn verification_cases_and_sentinels() {
    // Hard-coded independently from the fixture's status table.
    let expected: &[u8] = if cfg!(feature = "accelerated") {
        &[0, 1, 1, 1, 2, 3, 4]
    } else {
        &[0, 1, 1, 1, 2, 3]
    };
    assert_eq!(EXPECTED, expected);
    for (_, probe) in PROBES {
        for marker in [0x36, 0xa7] {
            let input = [marker; 256];
            let mut output = [0xa5; 64];
            for (case, status) in expected.iter().enumerate() {
                assert_eq!(probe(&input, &mut output, case), *status, "case {case}");
                assert_eq!(input, [marker; 256]);
                assert_eq!(output, [0xa5; 64]);
            }
            assert_eq!(probe(&input, &mut output, usize::MAX), 5);
        }
        assert_eq!(probe(&[0; 256], &mut [0xa5; 64], 0), 5);
        // Ignoring the message must not be masked by an oracle-only check.
        let mut wrong = [0x36; 256];
        wrong[134] ^= 1;
        assert_eq!(probe(&wrong, &mut [0xa5; 64], 0), 1);
    }
}

#[test]
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn observe_verification_returns_without_erasure_claim() {
    #[cfg(feature = "accelerated")]
    println!(
        "\nKMAC_VERIFY_ROUTE: {:?}",
        brynja_kmac_verify_caller::kernel()
    );
    #[cfg(not(feature = "accelerated"))]
    println!("\nKMAC_VERIFY_ROUTE: Portable");
    for (name, probe) in PROBES {
        for (case, expected) in EXPECTED.iter().enumerate() {
            let mut matches = 0;
            for marker in [0x36, 0xa7] {
                let input = [marker; 256];
                let mut output = [0xa5; 64];
                let snapshot = observer::capture(probe, &input, &mut output, case);
                assert_eq!(snapshot[0], *expected);
                assert_eq!(input, [marker; 256]);
                assert_eq!(output, [0xa5; 64]);
                matches += usize::from(observer::has_marker(&snapshot, marker));
            }
            println!(
                "\nKMAC_VERIFY_RETURN: {name}; case={case}; observations=2; input_marker_cases={matches}; qualifies_cleanup=false"
            );
        }
    }
}
