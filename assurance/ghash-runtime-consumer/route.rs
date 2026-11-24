use brynja_crypto::ghash::{Backend, Error, Ghash, Mode};

// Generated from the frozen NIST test in the checked Cargo archive.
include!("vectors.inc");

// All inputs are public fixtures. None of the expected values is computed by
// a Brynja backend, including on the portable-fallback path.
fn check_stream(
    h: &[u8; 16],
    input: &[u8],
    answer: Option<u128>,
    mode: Option<Mode>,
    backend: Backend,
) -> Result<(), Error> {
    for split in 0..=input.len() {
        let (mut work, mut out) = ([0x51; 16], [0xa7; 16]);
        let budget = u64::try_from(input.len()).unwrap();
        let mut owner = match mode {
            Some(mode) => Ghash::new_with_backend(h, &mut work, budget, mode)?,
            None => Ghash::new(h, &mut work, budget),
        };
        assert_eq!(owner.backend(), backend);
        let (left, right) = input.split_at(split);
        owner.update(left)?;
        // Reject a chunk one byte beyond the remaining budget. Continuing with
        // the genuine suffix must still produce the published result.
        assert_eq!(
            owner.update(&vec![0xee; right.len() + 1]),
            Err(Error::LimitExceeded)
        );
        owner.update(&[])?;
        owner.update(right)?;
        match answer {
            Some(value) => {
                let result = owner.finish(&mut out)?;
                assert_eq!(result.expose(), value.to_be_bytes(), "split {split}");
                result.clear();
                assert_eq!(out, [0; 16]);
            }
            None => {
                assert!(matches!(owner.finish(&mut out), Err(Error::PartialBlock)));
                assert_eq!(out, [0xa7; 16]);
            }
        }
        assert_eq!(work, [0; 16]);
    }
    Ok(())
}

fn check_vectors(mode: Option<Mode>, backend: Backend) -> Result<(), Error> {
    let h = 0x66e94bd4ef8a2c3b884cfa59ca342b2eu128.to_be_bytes();
    let stream = [0x0388dace60b6a392f328c2b971b2fe78u128, 128].map(u128::to_be_bytes);
    for len in 0..=32 {
        let answer = match len {
            0 => Some(0),
            16 => Some(0x5e2ec746917062882c85b0685353deb7),
            32 => Some(0xf38cbb1ad69223dcc3457ae5b6b0f885),
            _ => None,
        };
        check_stream(&h, &stream.as_flattened()[..len], answer, mode, backend)?;
    }
    for (subkey, cases) in PUBLISHED {
        for &(blocks, answer) in cases {
            let framed: Vec<_> = blocks.iter().copied().flat_map(u128::to_be_bytes).collect();
            check_stream(&subkey.to_be_bytes(), &framed, Some(answer), mode, backend)?;
        }
    }
    Ok(())
}

#[test]
fn route_contract() -> Result<(), Error> {
    let expected = std::env::var("BRYNJA_TEST_GHASH_ROUTE").expect("explicit test scenario");
    #[cfg(target_arch = "x86_64")]
    let native = Backend::Pclmul;
    #[cfg(target_arch = "riscv64")]
    let native = Backend::Rv64Zbc;
    #[cfg(target_arch = "aarch64")]
    let native = {
        use std::arch::is_aarch64_feature_detected;
        assert!(is_aarch64_feature_detected!("neon") && is_aarch64_feature_detected!("aes"));
        assert!(is_aarch64_feature_detected!("pmull"));
        // Absence on a PMULL-capable machine is a subtractive test control only.
        assert_eq!(cfg!(brynja_ghash_deny_pmull), expected == "absent");
        Backend::Pmull
    };
    #[cfg(target_arch = "x86_64")]
    if expected == "absent" {
        assert!(std::is_x86_feature_detected!("aes"));
        assert!(!std::is_x86_feature_detected!("pclmulqdq"));
    } else {
        assert!(std::is_x86_feature_detected!("pclmulqdq"));
    }
    #[cfg(target_arch = "riscv64")]
    {
        use std::arch::is_riscv_feature_detected;
        assert_eq!(is_riscv_feature_detected!("zbc"), expected != "absent");
        match std::env::var("BRYNJA_TEST_GHASH_RV64_MODEL").as_deref() {
            Ok("zbkc") => assert!(is_riscv_feature_detected!("zbkc")),
            Ok("aes") => {
                assert!(!is_riscv_feature_detected!("zbkc"));
                assert!(is_riscv_feature_detected!("zkne") && is_riscv_feature_detected!("zknd"));
            }
            Ok("zbc") => {
                assert!(is_riscv_feature_detected!("zbkc"));
                assert!(!is_riscv_feature_detected!("zkne") && !is_riscv_feature_detected!("zknd"));
            }
            Ok("hardware") => assert!(is_riscv_feature_detected!("zbc")),
            _ => panic!("missing RV64 test model"),
        }
    }
    let h = 0x66e94bd4ef8a2c3b884cfa59ca342b2eu128.to_be_bytes();
    check_vectors(None, Backend::Portable)?;
    for mode in [Mode::Require, Mode::Prefer] {
        let backend = match (expected.as_str(), mode) {
            ("quarantine", _) | ("absent", Mode::Require) => {
                let mut work = [0x51; 16];
                let selection = Ghash::new_with_backend(&h, &mut work, 32, mode);
                assert_eq!(
                    selection.err(),
                    Some(if expected == "absent" {
                        Error::Unavailable
                    } else {
                        Error::Quarantined
                    })
                );
                assert_eq!(work, [0x51; 16]);
                continue;
            }
            ("absent", Mode::Prefer) => Backend::Portable,
            ("native", _) => native,
            _ => panic!("unexpected scenario"),
        };
        check_vectors(Some(mode), backend)?;
    }
    Ok(())
}
