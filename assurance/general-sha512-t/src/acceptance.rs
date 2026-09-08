//! Package-external ordinary/hardened byte and bit API acceptance.
use brynja_hash_sha2::*;

/// An assertion failure is evidence failure, not a cryptographic error.
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid or incomplete assurance input.
    Corpus,
    /// An operation disagreed with its contract or independent expected bytes.
    Mismatch,
    /// A public API rejected valid assurance input.
    Api(Sha512TError),
}
impl From<Sha512TError> for Error {
    fn from(value: Sha512TError) -> Self {
        Self::Api(value)
    }
}
pub(crate) fn ensure(condition: bool) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::Mismatch)
    }
}
fn auth() -> PublicDeclassification {
    PublicDeclassification::acknowledge()
}
fn check(value: Sha512TDigest, p: Sha512TBits, expected: &[u8]) -> Result<(), Error> {
    ensure(value.parameter() == p && value.as_bytes() == expected && value.as_ref() == expected)
}
fn secret(
    value: Sha512TSecretDigest<'_>,
    p: Sha512TBits,
    expected: &[u8],
    declassify: bool,
) -> Result<(), Error> {
    ensure(value.parameter() == p && value.as_bytes() == expected)?;
    if declassify {
        check(value.declassify(auth())?, p, expected)?;
    }
    Ok(())
}

/// Compare each public output route with independent known bytes, not a round trip.
pub fn check_case(t: u16, bits: usize, message: &[u8], expected: &[u8]) -> Result<(), Error> {
    let p = Sha512TBits::new(t)?;
    ensure(expected.len() == p.output_bytes())?;
    let tail = u8::try_from(bits % 8).map_err(|_| Error::Corpus)?;
    ensure(message.len() == bits.div_ceil(8))?;
    let valid = if tail == 0 && !message.is_empty() {
        8
    } else {
        tail
    };
    let input = BitString::new(message, valid).map_err(|_| Error::Corpus)?;
    let (prefix, suffix) = message.split_at(bits / 8);
    let tail_input = BitString::new(suffix, tail).map_err(|_| Error::Corpus)?;
    check(sha512_t_bits(p, input)?, p, expected)?;
    check(
        hardened_sha512_t_bits_public(p, input, auth())?,
        p,
        expected,
    )?;
    // Independent poison before EACH route prevents stale-output false passes.
    let mut storage = [0_u8; 64];
    let output = storage.get_mut(..p.output_bytes()).ok_or(Error::Corpus)?;
    for (byte, answer) in output.iter_mut().zip(expected) {
        *byte = !answer;
    }
    secret(
        hardened_sha512_t_bits_secret(p, input, output)?,
        p,
        expected,
        false,
    )?;
    ensure(output.iter().all(|b| *b == 0))?;
    for stride in [1, 19, 128] {
        let mut ordinary = Sha512T::new(p);
        let mut public = HardenedSha512T::new(p);
        let mut confidential = HardenedSha512T::new(p);
        ordinary.update(&[])?;
        public.update(&[])?;
        confidential.update(&[])?;
        for chunk in prefix.chunks(stride) {
            ordinary.update(chunk)?;
            public.update(chunk)?;
            confidential.update(chunk)?;
        }
        ensure(ordinary.parameter() == p && public.parameter() == p)?;
        ensure(ordinary.message_bytes() == prefix.len() as u128)?;
        ensure(public.message_bytes() == prefix.len() as u128)?;
        check(ordinary.finalize_bits(tail_input)?, p, expected)?;
        check(
            public.finalize_bits_public(tail_input, auth())?,
            p,
            expected,
        )?;
        for (byte, answer) in output.iter_mut().zip(expected) {
            *byte = !answer;
        }
        secret(
            confidential.finalize_bits_secret(tail_input, output)?,
            p,
            expected,
            true,
        )?;
        ensure(output.iter().all(|b| *b == 0))?;
    }
    if tail == 0 {
        check(sha512_t(p, message)?, p, expected)?;
        check(hardened_sha512_t_public(p, message, auth())?, p, expected)?;
        for (byte, answer) in output.iter_mut().zip(expected) {
            *byte = !answer;
        }
        secret(
            hardened_sha512_t_secret(p, message, output)?,
            p,
            expected,
            false,
        )?;
        ensure(output.iter().all(|b| *b == 0))?;
        let mut ordinary = Sha512T::new(p);
        let mut public = HardenedSha512T::new(p);
        let mut confidential = HardenedSha512T::new(p);
        for chunk in message.chunks(2) {
            ordinary.update(chunk)?;
            public.update(chunk)?;
            confidential.update(chunk)?;
        }
        check(ordinary.finalize()?, p, expected)?;
        check(public.finalize_public(auth())?, p, expected)?;
        for (byte, answer) in output.iter_mut().zip(expected) {
            *byte = !answer;
        }
        secret(confidential.finalize_secret(output)?, p, expected, true)?;
        ensure(output.iter().all(|b| *b == 0))?;
        if t == 224 {
            ensure(sha512_224(message).map_err(|_| Error::Mismatch)?.as_bytes() == expected)?;
        }
        if t == 256 {
            ensure(sha512_256(message).map_err(|_| Error::Mismatch)?.as_bytes() == expected)?;
        }
    }
    check(Sha512TDigest::from_bytes(p, expected)?, p, expected)?;
    Ok(())
}

/// Fixed corpus acceptance with exact ordering/count/length constraints.
/// Caller supplies the pinned independent oracle corpus; no allocation is used.
pub fn run(corpus: &str) -> Result<usize, Error> {
    crate::boundaries::check()?;
    crate::corpus::run(corpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_routes_and_corrupted_answer() -> Result<(), Error> {
        // Independent pinned t=1 empty-message case, including all byte routes.
        check_case(1, 0, &[], &[0x80])?;
        ensure(check_case(1, 0, &[], &[0]).is_err())?;
        ensure(check_case(1, usize::MAX, &[], &[0x80]).is_err())?;
        ensure(check_case(384, 0, &[], &[0]).is_err())?;
        Ok(())
    }
}
