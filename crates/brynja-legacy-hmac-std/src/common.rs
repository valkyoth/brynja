//! Shared algorithms for the distinct protected and resident wrappers.
// Expand the same straight-line validation at each worker entry. Keeping the
// existing local lifetimes avoids an extra Result/tuple temporary around secret
// owner construction while leaving only one maintained copy of the algorithm.
macro_rules! split_tail {
    ($request:ident, $complete:ident, $tail:ident, $error:ident) => {
        let _ = brynja_legacy_hmac::BitString::new($request.tail.bytes, $request.tail.valid_bits)
            .map_err(|_| $error::InvalidBits)?;
        let split = if $request.tail.valid_bits == 8 || $request.tail.bytes.is_empty() {
            $request.tail.bytes.len()
        } else {
            $request
                .tail
                .bytes
                .len()
                .checked_sub(1)
                .ok_or($error::InvalidBits)?
        };
        let ($complete, partial) = $request
            .tail
            .bytes
            .split_at_checked(split)
            .ok_or($error::Invariant)?;
        let $tail = brynja_legacy_hmac::BitString::new(
            partial,
            if partial.is_empty() {
                0
            } else {
                $request.tail.valid_bits
            },
        )
        .map_err(|_| $error::InvalidBits)?;
    };
}
pub(crate) use split_tail;

// Private worker transport only. Public hosted verification converts a false
// decision back to Err(Mismatch); no public verification returns Ok(false).
#[inline(always)]
pub(crate) fn verification_decision(
    result: Result<(), brynja_legacy_hmac::VerificationError>,
) -> Result<bool, brynja_legacy_hmac::Error> {
    match result {
        Ok(()) => Ok(true),
        Err(brynja_legacy_hmac::VerificationError::Mismatch(())) => Ok(false),
        Err(brynja_legacy_hmac::VerificationError::Operation(error)) => Err(error),
    }
}

#[cfg(any(feature = "strict-md5-batch", feature = "macos-resident-md5-batch"))]
pub(crate) const fn recoverable_md5(error: brynja_legacy_hmac::Error) -> bool {
    matches!(
        error,
        brynja_legacy_hmac::Error::Cancelled
            | brynja_legacy_hmac::Error::WorkLimit
            | brynja_legacy_hmac::Error::MessageTooLong
    )
}

#[cfg(test)]
mod tests {
    use brynja_legacy_hmac::BitString;
    #[derive(Debug, PartialEq)]
    enum Error {
        InvalidBits,
        Invariant,
    }
    struct Bits<'a> {
        bytes: &'a [u8],
        valid_bits: u8,
    }
    struct Request<'a> {
        tail: Bits<'a>,
    }
    fn split(bytes: &[u8], valid_bits: u8) -> Result<(&[u8], BitString<'_>), Error> {
        let request = Request {
            tail: Bits { bytes, valid_bits },
        };
        super::split_tail!(request, complete, tail, Error);
        Ok((complete, tail))
    }
    #[test]
    fn tail_validation_preserves_order_and_canonical_bits() -> Result<(), Error> {
        for bits in 0..=9 {
            for length in 0..=3 {
                for last in 0..=255u8 {
                    let mut bytes = [0x91, 0x27, last];
                    if length != 0 {
                        *bytes.get_mut(length - 1).ok_or(Error::Invariant)? = last;
                    }
                    let input = bytes.get(..length).ok_or(Error::Invariant)?;
                    let actual = split(input, bits);
                    let valid = BitString::new(input, bits).is_ok();
                    assert_eq!(actual.is_ok(), valid);
                    if let Ok((complete, tail)) = actual {
                        let expected = if bits == 8 || length == 0 {
                            length
                        } else {
                            length - 1
                        };
                        assert_eq!(Some(complete), input.get(..expected));
                        assert_eq!(
                            tail.bit_len(),
                            if expected == length {
                                0
                            } else {
                                usize::from(bits)
                            }
                        );
                    } else {
                        assert!(matches!(actual, Err(Error::InvalidBits)));
                    }
                }
            }
        }
        Ok(())
    }
}
