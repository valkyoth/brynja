use super::polynomial_product;
use brynja_crypto::ghash::{Error, Ghash};

#[test]
fn native_blocks_match_wire_oracle_at_every_split() -> Result<(), Error> {
    let mut seed = 0xe125a1fce15d6cc7u128;
    let mut next = || {
        seed ^= seed << 23;
        seed ^= seed >> 17;
        seed ^= seed << 26;
        seed
    };
    for _ in 0..64 {
        let h = next();
        let blocks = [next(), next(), next()];
        let expected = blocks
            .into_iter()
            .fold(0, |y, x| polynomial_product(y ^ x, h));
        let wire = blocks.map(u128::to_be_bytes);
        let h = h.to_be_bytes();
        for split in 0..=48 {
            let (mut work, mut output) = ([0x55; 16], [0xa5; 16]);
            let mut hash = Ghash::new(&h, &mut work, 48);
            let (prefix, suffix) = wire.as_flattened().split_at(split);
            hash.update(prefix)?;
            hash.update(&[])?;
            assert_eq!(hash.native_blocks()?, (split / 16) as u64);
            // Too long even at offset zero, with enough complete blocks to
            // detect an implementation that consumes before checking budget.
            assert_eq!(hash.update(&[0xff; 49]), Err(Error::LimitExceeded));
            assert_eq!(hash.native_blocks()?, (split / 16) as u64);
            hash.update(suffix)?;
            assert_eq!(hash.native_blocks()?, 3);
            let out = hash.finish(&mut output)?;
            assert_eq!(out.expose(), expected.to_be_bytes());
            assert_eq!(work, [0; 16]);
            out.clear();
            assert_eq!(output, [0; 16]);
        }
    }
    Ok(())
}

#[test]
fn partial_block_never_executes_a_product_or_releases_output() -> Result<(), Error> {
    for tail in 1..16 {
        let (mut work, mut output) = ([0xff; 16], [0xa5; 16]);
        let key = [0x37; 16];
        let mut hash = Ghash::new(&key, &mut work, u64::MAX);
        hash.update(&[0x12; 32])?;
        hash.update([0xab; 16].split_at(tail).0)?;
        assert_eq!(hash.native_blocks()?, 2);
        assert!(matches!(hash.finish(&mut output), Err(Error::PartialBlock)));
        assert_eq!(work, [0; 16]);
        assert_eq!(output, [0xa5; 16]);
    }
    Ok(())
}

#[cfg(all(brynja_cpu_evidence, target_arch = "x86_64"))]
#[test]
fn missing_pclmul_fails_closed_even_on_empty_finish() {
    assert!(std::is_x86_feature_detected!("aes"));
    assert!(!std::is_x86_feature_detected!("pclmulqdq"));
    unavailable_owner();
}

#[cfg(all(brynja_ghash_pmull_evidence, brynja_ghash_deny_pmull))]
#[test]
fn masked_pmull_fails_closed_even_on_empty_finish() {
    // A positive host makes this a denial control, not a second positive run.
    assert!(std::arch::is_aarch64_feature_detected!("pmull"));
    unavailable_owner();
}

#[cfg(all(brynja_ghash_rv64_evidence, brynja_cpu_evidence))]
#[test]
fn emulated_owner_respects_reported_features() -> Result<(), &'static str> {
    use std::arch::is_riscv_feature_detected;
    let actual = (
        is_riscv_feature_detected!("zbc"),
        is_riscv_feature_detected!("zbkc"),
        is_riscv_feature_detected!("zkne"),
        is_riscv_feature_detected!("zknd"),
    );
    match std::env::var("BRYNJA_GHASH_RV64_MODEL").as_deref() {
        Ok("both") => assert_eq!(actual, (true, true, false, false)),
        Ok("zbkc") => assert_eq!(actual, (false, true, false, false)),
        Ok("neither") => {
            assert_eq!(actual, (false, false, true, true));
            unavailable_owner();
            return Ok(());
        }
        _ => return Err("missing model for emulated RV64 owner test"),
    }
    let mut work = [0; 16];
    assert_eq!(Ghash::new(&[0x37; 16], &mut work, 0).native_blocks(), Ok(0));
    Ok(())
}

#[cfg(any(
    all(brynja_cpu_evidence, target_arch = "x86_64"),
    all(brynja_ghash_rv64_evidence, brynja_cpu_evidence),
    all(brynja_ghash_pmull_evidence, brynja_ghash_deny_pmull)
))]
fn unavailable_owner() {
    let (mut work, mut output) = ([0xff; 16], [0xa5; 16]);
    let mut hash = Ghash::new(&[0x37; 16], &mut work, 16);
    assert_eq!(hash.native_blocks(), Err(Error::CandidateNotReady));
    assert_eq!(hash.update(&[]), Err(Error::CandidateNotReady));
    assert_eq!(hash.update(&[0; 16]), Err(Error::CandidateNotReady));
    assert!(matches!(
        hash.finish(&mut output),
        Err(Error::CandidateNotReady)
    ));
    assert_eq!(work, [0; 16]);
    assert_eq!(output, [0xa5; 16]);
}
