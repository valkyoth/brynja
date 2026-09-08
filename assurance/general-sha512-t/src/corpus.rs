use crate::acceptance::{Error, check_case};

fn hex(text: &str, storage: &mut [u8]) -> Result<usize, Error> {
    if text == "-" {
        return Ok(0);
    }
    if text.is_empty() || !text.len().is_multiple_of(2) || text.len() / 2 > storage.len() {
        return Err(Error::Corpus);
    }
    let digit = |b| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(Error::Corpus),
    };
    for ([a, b], slot) in text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .zip(storage.iter_mut())
    {
        *slot = (digit(*a)? << 4) | digit(*b)?;
    }
    Ok(text.len() / 2)
}

pub(crate) fn run(corpus: &str) -> Result<usize, Error> {
    visit(corpus, check_case)
}

pub(crate) fn visit<F>(corpus: &str, mut check: F) -> Result<usize, Error>
where
    F: FnMut(u16, usize, &[u8], &[u8]) -> Result<(), Error>,
{
    if corpus.len() > 3_000_000 {
        return Err(Error::Corpus);
    }
    let mut rows = corpus.lines();
    let mut count = 0;
    for t in (1_u16..512).filter(|t| *t != 384) {
        for bits in [0_usize, 24, 889, 898, 1019, 1028, 1037, 2046, 2055] {
            let row = rows.next().ok_or(Error::Corpus)?;
            if row.len() > 1024 {
                return Err(Error::Corpus);
            }
            let mut fields = row.split_ascii_whitespace();
            let actual_t = fields
                .next()
                .ok_or(Error::Corpus)?
                .parse::<u16>()
                .map_err(|_| Error::Corpus)?;
            let actual_bits = fields
                .next()
                .ok_or(Error::Corpus)?
                .parse::<usize>()
                .map_err(|_| Error::Corpus)?;
            if actual_t != t || actual_bits != bits {
                return Err(Error::Corpus);
            }
            let mut message = [0; 257];
            let mut expected = [0; 64];
            let m = hex(fields.next().ok_or(Error::Corpus)?, &mut message)?;
            let n = hex(fields.next().ok_or(Error::Corpus)?, &mut expected)?;
            if m != bits.div_ceil(8) || n != usize::from(t).div_ceil(8) {
                return Err(Error::Corpus);
            }
            if fields.next().is_some() {
                return Err(Error::Corpus);
            }
            check(
                t,
                bits,
                message.get(..m).ok_or(Error::Corpus)?,
                expected.get(..n).ok_or(Error::Corpus)?,
            )?;
            count += 1;
        }
    }
    if rows.next().is_some() {
        return Err(Error::Corpus);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn visitors_never_receive_mismatched_message_or_digest_widths() {
        for input in ["1 0 aa 80", "1 0 - -", "1 0 - aabb"] {
            let mut calls = 0;
            assert!(
                visit(input, |_, _, _, _| {
                    calls += 1;
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(calls, 0);
        }
        for corpus in [
            "1 0 - 80\n1 24 - 00",
            "1 0 - 80\n1 24 00 00",
            "1 0 - 80\n1 24 0000 00",
            "1 0 - 80\n1 24 00000000 00",
        ] {
            let mut calls = 0;
            assert!(
                visit(corpus, |_, _, _, _| {
                    calls += 1;
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(calls, 1);
        }
    }
    #[test]
    fn malformed_input_is_rejected() {
        for input in [
            "",
            "1 0 -",
            "384 0 - 00",
            "1 0 - gg",
            "1 0 - 0",
            "1 0 - 00 extra",
            "1 18446744073709551616 - 00",
        ] {
            assert!(run(input).is_err());
        }
        assert!(hex("aabb", &mut [0]).is_err());
    }
}
