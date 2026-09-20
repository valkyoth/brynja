//! Independently generated ParallelHash values, B=8, input 0..127, empty S, L=256.
use brynja_caller_residue_audit::{PROBES, threaded};

const GOLDENS: [(&str, &str); 4] = [
    (
        "128",
        "c645a01f019309b3201eaf4675b04f3697073f16d1674099f46be388ed50a327",
    ),
    (
        "256",
        "96a3b7d69cb5e84c131d41ac3fbaeebb451c8e1732bededb0d86c66739f8b083",
    ),
    (
        "xof128",
        "94bdc36165bb92bad75d4693db973d9b3d24140253ff8e5d580442b2d6b16927",
    ),
    (
        "xof256",
        "f9525ef7b00815b704e7d030a7ca636b85567c4b4c486920ca9e3a018652da38",
    ),
];

#[test]
fn threaded_workers_match_independent_vectors_before_secret_drop() {
    let mut input = [0; 256];
    for (byte, value) in input.iter_mut().zip(0..=u8::MAX) {
        *byte = value;
    }
    for (identity, hex) in GOLDENS {
        let expected: Vec<_> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let nibble = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid synthetic test vector"),
                };
                (nibble(pair[0]) << 4) | nibble(pair[1])
            })
            .collect();
        for prefix in ["portable", "static", "batch"] {
            let name = format!("{prefix}{identity}");
            let mut output = [0xa5; 64];
            assert_eq!(
                threaded::check_known(&name, &input, &mut output, &expected),
                0,
                "{name}"
            );
            assert_eq!(&output[..32], &[0; 32]);
            assert_eq!(&output[32..], &[0xa5; 32]);
            let mut wrong = expected.clone();
            wrong[0] ^= 1;
            assert_eq!(
                threaded::check_known(&name, &input, &mut output, &wrong),
                3,
                "{name}"
            );
            assert_eq!(&output[..32], &[0; 32]);
        }
    }
}

#[test]
fn threaded_cancellation_and_ineligible_batch_clear_without_fallback() {
    use brynja_crypto_cpu::static_execution::{Health, Report as KernelReport};
    use brynja_hash_parallel_std::execution::Report;
    for route in [
        threaded::Route::Portable,
        threaded::Route::Static,
        threaded::Route::Batch,
    ] {
        let portable = route == threaded::Route::Portable;
        let root = if portable {
            None
        } else {
            Some(KernelReport {
                kernel: brynja_caller_residue_audit::accelerated::kernel(),
                health: Health::Healthy,
                generation: 0,
            })
        };
        let valid = Report {
            root,
            leaves: 16,
            accelerated_leaves: if portable { 0 } else { 16 },
            thread_width: 2,
        };
        assert!(threaded::checked_report(valid, route, 16));
        for bad in [
            Report {
                leaves: 15,
                ..valid
            },
            Report {
                thread_width: 1,
                ..valid
            },
            Report {
                accelerated_leaves: 7,
                ..valid
            },
        ] {
            assert!(!threaded::checked_report(bad, route, 16));
        }
        if let Some(mut invalid) = root {
            invalid.health = Health::Quarantined;
            assert!(!threaded::checked_report(
                Report {
                    root: Some(invalid),
                    ..valid
                },
                route,
                16
            ));
            assert!(!threaded::checked_report(
                Report {
                    root: None,
                    ..valid
                },
                route,
                16
            ));
        }
    }
    for (name, probe, _) in PROBES {
        let input = [0x36; 256];
        let mut output = [0xa5; 64];
        assert_eq!(
            threaded::check_cancelled(name, &input, &mut output),
            1,
            "{name}"
        );
        assert_eq!(&output[..32], &[0; 32]);
        assert_eq!(&output[32..], &[0xa5; 32]);
        if name.starts_with("batch") {
            output.fill(0xa5);
            assert_eq!(probe(&input, &mut output, 1), 1, "{name}");
            assert_eq!(&output[..32], &[0; 32]);
            assert_eq!(&output[32..], &[0xa5; 32]);
        }
        assert_eq!(input, [0x36; 256]);
    }
    println!(
        "\nCALLER_THREADS: kernel={:?}; workers=2; block=8; profiles=portable,static,batch; coordinator_only=true",
        brynja_caller_residue_audit::accelerated::kernel()
    );
}
