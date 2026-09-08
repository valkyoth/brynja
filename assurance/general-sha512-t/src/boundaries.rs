use crate::acceptance::{Error, ensure};
use brynja_hash_sha2::*;

pub(crate) fn check() -> Result<(), Error> {
    for t in 0..=u16::MAX {
        ensure(Sha512TBits::new(t).is_ok() == (t > 0 && t < 512 && t != 384))?;
    }
    for t in (1..512).filter(|t| *t != 384) {
        let p = Sha512TBits::try_from(t)?;
        let mut label = [0xa5; 12];
        let used = p.write_iv_label(&mut label)?;
        ensure(label.get(..8) == Some(b"SHA-512/"))?;
        let decimal = core::str::from_utf8(label.get(8..used).ok_or(Error::Corpus)?)
            .map_err(|_| Error::Corpus)?;
        ensure(
            !decimal.starts_with('0') && decimal.parse::<u16>().map_err(|_| Error::Corpus)? == t,
        )?;
        ensure(label.get(used..) == Some(&[0xa5; 12][..12 - used]))?;
        let mut short = [0xa5; 8];
        ensure(p.write_iv_label(&mut short) == Err(Sha512TError::OutputLength))?;
        ensure(short == [0xa5; 8])?;
        let mut ordinary = Sha512T::new(p);
        let mut hard = HardenedSha512T::new(p);
        ordinary.update(b"abc")?;
        hard.update(b"abc")?;
        ensure(ordinary.check_additional_bytes(u128::MAX) == Err(Sha512TError::MessageTooLong))?;
        ensure(ordinary.check_additional_bits(u128::MAX) == Err(Sha512TError::MessageTooLong))?;
        ensure(hard.check_additional_bytes(u128::MAX) == Err(Sha512TError::MessageTooLong))?;
        ensure(hard.check_additional_bits(u128::MAX) == Err(Sha512TError::MessageTooLong))?;
        ensure(ordinary.message_bytes() == 3 && hard.message_bytes() == 3)?;
        ensure(
            ordinary.finalize()? == hard.finalize_public(PublicDeclassification::acknowledge())?,
        )?;
        HardenedSha512T::new(p).cancel();
        // Every destination size, all four secret-producing entry points.
        for width in 0..=65 {
            if width == p.output_bytes() {
                continue;
            }
            let imported = [0; 65];
            ensure(
                Sha512TDigest::from_bytes(p, imported.get(..width).ok_or(Error::Corpus)?)
                    == Err(Sha512TError::OutputLength),
            )?;
            for route in 0..4 {
                let mut guarded = [0xa5; 67];
                let output = guarded.get_mut(1..1 + width).ok_or(Error::Corpus)?;
                let bits = BitString::new(b"abc", 8).map_err(|_| Error::Corpus)?;
                let result = match route {
                    0 => hardened_sha512_t_secret(p, b"abc", output),
                    1 => hardened_sha512_t_bits_secret(p, bits, output),
                    2 => HardenedSha512T::new(p).finalize_secret(output),
                    _ => HardenedSha512T::new(p).finalize_bits_secret(bits, output),
                };
                ensure(matches!(result, Err(Sha512TError::OutputLength)))?;
                drop(result);
                ensure(output.iter().all(|b| *b == 0))?;
                ensure(guarded.first() == Some(&0xa5))?;
                ensure(
                    guarded
                        .get(1 + width..)
                        .is_some_and(|s| s.iter().all(|b| *b == 0xa5)),
                )?;
            }
        }
        if t % 8 != 0 {
            let mut bytes = [0; 64];
            let output = bytes.get_mut(..p.output_bytes()).ok_or(Error::Corpus)?;
            *output.last_mut().ok_or(Error::Corpus)? = 1;
            ensure(Sha512TDigest::from_bytes(p, output) == Err(Sha512TError::NonCanonicalOutput))?;
        }
    }
    ensure(BitString::new(&[1], 1).is_err())?;
    ensure(BitString::new(&[0], 9).is_err())?;
    Ok(())
}
