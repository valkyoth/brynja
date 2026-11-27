use super::*;

// Reproducible public input for framing and injected-error tests, not a
// sender nonce allocator. Known-answer tests use the published IV instead.
pub(super) fn sample_iv<const N: usize>() -> [u8; N] {
    core::array::from_fn(|i| i.to_le_bytes()[0])
}

#[test]
fn frame_admits_whole_updates_before_notifying_any_route() -> Result<(), Error> {
    struct Count(core::cell::Cell<u8>);
    impl HashRoute for Count {
        fn start<'a>(
            &self,
            h: &'a [u8; 16],
            state: &'a mut [u8; 16],
            budget: u64,
        ) -> Result<Ghash<'a>, Error> {
            Ok(Ghash::new(h, state, budget))
        }
        fn after_update(&self) -> Result<(), Error> {
            self.0.set(self.0.get().saturating_add(1));
            Ok(())
        }
    }
    let route = Count(core::cell::Cell::new(0));
    let mut out = [0xa5; 16];
    let mut frame = Frame::lengths(17, 0)?;
    frame.budget = 16;
    TEST_STARTS.set(0);
    assert!(matches!(
        frame.hash(&route, &[0; 16], &[1; 17], &[], &mut out),
        Err(Error::LimitExceeded)
    ));
    assert_eq!((TEST_STARTS.get(), route.0.get(), out), (1, 0, [0xa5; 16]));
    Frame::lengths(17, 0)?
        .hash(&route, &[0; 16], &[1; 17], &[], &mut out)?
        .clear();
    // One whole field, its padding, and the two encoded lengths.
    assert_eq!((TEST_STARTS.get(), route.0.get()), (2, 4));
    Ok(())
}

#[test]
fn public_length_admission_without_large_allocations() -> Result<(), Error> {
    let max = u64::MAX / 8;
    let frame = Frame::message(max, MAX_TEXT_BYTES)?;
    assert_eq!(frame.left_bits, u64::MAX - 7);
    assert_eq!(frame.right_bits, (1u64 << 39) - 256);
    assert_eq!(frame.budget, (1u64 << 61) + MAX_TEXT_BYTES + 16);
    assert!(Frame::message(max + 1, 0).is_err());
    assert!(Frame::message(0, MAX_TEXT_BYTES + 1).is_err());
    assert!(Frame::lengths(0, max + 1).is_err());
    Ok(())
}

#[test]
fn iv_fast_path_and_low_word_wrap() -> Result<(), Error> {
    let mut out = [0xa5; 16];
    assert!(initial_counter(&PortableHash, &[0; 16], &[], &mut out).is_err());
    let iv = sample_iv::<12>();
    let InitialCounter::FromPublicIv(mut j0) =
        initial_counter(&PortableHash, &[0; 16], &iv, &mut out)?
    else {
        return Err(Error::LimitExceeded);
    };
    assert_eq!(&j0[..12], &iv);
    assert_eq!(&j0[12..], &[0, 0, 0, 1]);
    inc32(&mut j0);
    assert_eq!(&j0[12..], &[0, 0, 0, 2]);
    j0[12..].fill(0xff);
    inc32(&mut j0);
    assert_eq!(&j0[..12], &iv);
    assert_eq!(&j0[12..], &[0; 4]);
    assert_eq!(out, [0xa5; 16]);
    Ok(())
}

#[test]
fn general_iv_and_split_fields_cover_every_padding_length() -> Result<(), Error> {
    // GHASH's multiplicative identity makes the independent oracle a block XOR.
    let h = (1u128 << 127).to_be_bytes();
    let mut out = [0xa5; 16];
    let sample = sample_iv::<33>();
    for n in (1..=33).filter(|&n| n != 12) {
        let iv = sample.get(..n).ok_or(Error::LimitExceeded)?;
        let mut expected = (n as u128 * 8).to_be_bytes();
        for block in iv.chunks(16) {
            for (slot, b) in expected.iter_mut().zip(block) {
                *slot ^= b;
            }
        }
        let InitialCounter::FromSecretHash(hash) =
            initial_counter(&PortableHash, &h, iv, &mut out)?
        else {
            return Err(Error::LimitExceeded);
        };
        assert_eq!(hash.expose(), expected);
        hash.clear();
        assert_eq!(out, [0; 16]);
    }
    for a in 0..=17 {
        for c in 0..=17 {
            let aad = [0x57; 17].get(..a).ok_or(Error::LimitExceeded)?;
            let ct = [0x38; 17].get(..c).ok_or(Error::LimitExceeded)?;
            let mut expected = (((a as u128 * 8) << 64) | (c as u128 * 8)).to_be_bytes();
            for field in [aad, ct] {
                for block in field.chunks(16) {
                    for (slot, b) in expected.iter_mut().zip(block) {
                        *slot ^= b;
                    }
                }
            }
            assert_eq!(auth_hash(&h, aad, ct, &mut out)?.expose(), expected);
            assert_eq!(out, [0; 16]);
        }
    }
    Ok(())
}

#[test]
fn nist_aes128_example_5_hashes_unpadded_inputs() -> Result<(), Error> {
    // NIST GCM worked examples, AES-128 example 5: 20 AAD and 60 CT bytes.
    let h = 0xb83b533708bf535d0aa6e52980d53b78u128.to_be_bytes();
    let aad = [
        0x3ad77bb40d7a3660a89ecaf32466ef97u128,
        0xf5d3d585000000000000000000000000,
    ]
    .map(u128::to_be_bytes);
    let ct = [
        0x42831ec2217774244b7221b784d0d49cu128,
        0xe3aa212f2c02a4e035c17e2329aca12e,
        0x21d514b25466931c7d8f6a5aac84aa05,
        0x1ba30b396a0aac973d58e09100000000,
    ]
    .map(u128::to_be_bytes);
    let mut out = [0xa5; 16];
    let hash = auth_hash(
        &h,
        aad.as_flattened()
            .first_chunk::<20>()
            .ok_or(Error::LimitExceeded)?,
        ct.as_flattened()
            .first_chunk::<60>()
            .ok_or(Error::LimitExceeded)?,
        &mut out,
    )?;
    assert_eq!(
        hash.expose(),
        0xc23b3d63d2ed95056ca342769cd13c03u128.to_be_bytes()
    );
    Ok(())
}
