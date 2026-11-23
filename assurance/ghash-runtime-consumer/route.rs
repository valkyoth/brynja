use brynja_crypto::ghash::{Backend, Error, Ghash, Mode};

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
    let block = 0x0388dace60b6a392f328c2b971b2fe78u128.to_be_bytes();
    let answer = 0x5e2ec746917062882c85b0685353deb7u128.to_be_bytes();
    let (mut work, mut out) = ([0x51; 16], [0xa7; 16]);
    let mut portable = Ghash::new(&h, &mut work, 16);
    assert_eq!(portable.backend(), Backend::Portable);
    portable.update(&block)?;
    assert_eq!(portable.finish(&mut out)?.expose(), answer);
    for mode in [Mode::Require, Mode::Prefer] {
        work.fill(0x51);
        let selection = Ghash::new_with_backend(&h, &mut work, 32, mode);
        let backend = match (expected.as_str(), mode) {
            ("quarantine", _) | ("absent", Mode::Require) => {
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
        let mut owner = selection?;
        assert_eq!(owner.backend(), backend);
        owner.update(&block[..5])?;
        assert_eq!(owner.update(&[0; 28]), Err(Error::LimitExceeded));
        owner.update(&block[5..])?;
        owner.update(&128_u128.to_be_bytes())?;
        let result = owner.finish(&mut out)?;
        // Second product consumes the carried state and GCM length block,
        // so the startup KAT value alone cannot satisfy this check.
        assert_eq!(
            result.expose(),
            0xf38cbb1ad69223dcc3457ae5b6b0f885u128.to_be_bytes()
        );
        result.clear();
        assert_eq!((work, out), ([0; 16], [0; 16]));
    }
    Ok(())
}
