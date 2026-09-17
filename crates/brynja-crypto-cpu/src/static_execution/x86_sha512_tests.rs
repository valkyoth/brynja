use super::{Authority, Error, Kernel};
#[cfg(target_arch = "x86_64")]
use super::{Health, PublicData};

#[test]
fn dedicated_sha512_requires_its_own_complete_bundle() {
    let expected = if !cfg!(target_arch = "x86_64") {
        Err(Error::WrongArchitecture)
    } else if !cfg!(all(
        target_feature = "sha512",
        target_feature = "avx2",
        target_feature = "avx"
    )) {
        Err(Error::MissingTargetFeatures)
    } else {
        Ok(())
    };
    assert_eq!(Kernel::X86Sha512.check_compiled_target(), expected);
    if let Err(error) = expected {
        assert_eq!(Authority::new(Kernel::X86Sha512).err(), Some(error));
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
#[cfg_attr(
    not(all(
        target_feature = "sha512",
        target_feature = "avx2",
        target_feature = "avx"
    )),
    ignore = "requires compiled SHA512/AVX2/AVX and compatible CPU or SDE; NOT execution evidence"
)]
fn dedicated_sha512_arbitrary_state_differential() -> Result<(), Error> {
    let required = std::env::var_os("BRYNJA_REQUIRE_X86_SHA512").is_some();
    if Kernel::X86Sha512.check_compiled_target().is_err() {
        assert!(!required, "required SHA512 execution must not be skipped");
        return Ok(());
    }
    let owner = Authority::new(Kernel::X86Sha512)?;
    assert_eq!(owner.report().health, Health::Healthy);
    let session = owner.session()?;
    let mut seed = 0xa617_d28b_956f_04c3_u64;
    for case in 0..1024 {
        let mut state = [0_u64; 8];
        let mut block = [0_u8; 128];
        for word in &mut state {
            *word = random(&mut seed);
        }
        for byte in &mut block {
            *byte = random(&mut seed).to_le_bytes()[0];
        }
        // Include zero and maximum words, independent of a standard IV.
        if case < 2 {
            state.fill(if case == 0 { 0 } else { u64::MAX });
            block.fill(if case == 0 { 0 } else { u8::MAX });
        }
        let mut expected = state;
        reference(&mut expected, &block)?;
        session.compress_sha512(PublicData::new(&mut state), PublicData::new(&block))?;
        assert_eq!(state, expected, "arbitrary chaining state case {case}");
    }
    owner.quarantine();
    let mut state = [0xa5; 8];
    assert_eq!(
        session.compress_sha512(PublicData::new(&mut state), PublicData::new(&[0; 128])),
        Err(Error::Quarantined)
    );
    assert_eq!(state, [0xa5; 8]);
    std::println!("DEDICATED_X86_SHA512: blocks=1024; quarantine=PASS");
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn random(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

// Test-only scalar FIPS 180-4 recurrence, not the intrinsic schedule or route.
#[cfg(target_arch = "x86_64")]
fn reference(state: &mut [u64; 8], block: &[u8; 128]) -> Result<(), Error> {
    let mut schedule = [0_u64; 80];
    for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*bytes);
    }
    for t in 16_usize..80 {
        let at = |back| {
            schedule
                .get(t.saturating_sub(back))
                .copied()
                .ok_or(Error::Quarantined)
        };
        let x = at(15)?;
        let y = at(2)?;
        let value = at(16)?
            .wrapping_add(at(7)?)
            .wrapping_add(x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7))
            .wrapping_add(y.rotate_right(19) ^ y.rotate_right(61) ^ (y >> 6));
        *schedule.get_mut(t).ok_or(Error::Quarantined)? = value;
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (word, constant) in schedule
        .into_iter()
        .zip(crate::sha512_schedule::ROUND_CONSTANTS)
    {
        let t1 = h
            .wrapping_add(e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41))
            .wrapping_add((e & f) ^ (!e & g))
            .wrapping_add(constant)
            .wrapping_add(word);
        let t2 = (a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39))
            .wrapping_add((a & b) ^ (a & c) ^ (b & c));
        (a, b, c, d, e, f, g, h) = (t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g);
    }
    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
    Ok(())
}
