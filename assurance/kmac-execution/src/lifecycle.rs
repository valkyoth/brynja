use crate::selection::Selection;
use brynja_mac_kmac::{Fips202BitString, KmacPublicDeclassification, execution as api};
use std::io;

fn fail(error: impl core::fmt::Debug) -> io::Error {
    io::Error::other(format!("KMAC lifecycle: {error:?}"))
}

pub struct Case<'a> {
    pub algorithm: &'a str,
    pub key: Fips202BitString<'a>,
    pub custom: Fips202BitString<'a>,
    pub message: Fips202BitString<'a>,
    pub valid: u8,
    pub expected: &'a [u8],
}

pub fn check(case: Case<'_>, selection: &Selection) -> Result<(), io::Error> {
    let Case {
        algorithm,
        key,
        custom,
        message,
        valid,
        expected,
    } = case;
    let complete = if message.is_byte_aligned() {
        message.as_bytes().len()
    } else {
        message.as_bytes().len().saturating_sub(1)
    };
    let (prefix, final_bytes) = message.as_bytes().split_at(complete);
    let tail = Fips202BitString::new(
        final_bytes,
        if final_bytes.is_empty() {
            0
        } else {
            message.valid_bits_in_last_byte()
        },
    )
    .map_err(fail)?;
    let mut storage = [0xa5_u8; 512];
    let bytes = storage
        .get_mut(..expected.len())
        .ok_or_else(|| fail("output bound"))?;
    // Poison every output byte with a value guaranteed different from its oracle.
    for (byte, value) in bytes.iter_mut().zip(expected) {
        *byte = !value;
    }
    macro_rules! fixed {
        ($name:ident) => {{
            let mut state =
                api::$name::new_bits_conformance(selection.mode()?, key, custom).map_err(fail)?;
            selection.check_actual(state.report())?;
            for chunk in prefix.chunks(7) {
                state.update(&[]).map_err(fail)?;
                state.update(chunk).map_err(fail)?;
            }
            let secret = state
                .finalize_secret_bits_conformance(tail, bytes, valid)
                .map_err(fail)?;
            if secret.expose() != expected {
                return Err(fail("fixed secret/stream mismatch"));
            }
            drop(secret);
            let candidate = Fips202BitString::new(expected, valid).map_err(fail)?;
            if !api::$name::new_bits_conformance(selection.mode()?, key, custom)
                .map_err(fail)?
                .verify_bits_conformance(message, candidate)
                .map_err(fail)?
                .expose_public()
            {
                return Err(fail("correct tag rejected"));
            }
            if !expected.is_empty() {
                for index in [0, expected.len().saturating_sub(1)] {
                    bytes.copy_from_slice(expected);
                    bytes[index] ^= 1;
                    let candidate = Fips202BitString::new(bytes, valid).map_err(fail)?;
                    if api::$name::new_bits_conformance(selection.mode()?, key, custom)
                        .map_err(fail)?
                        .verify_bits_conformance(message, candidate)
                        .map_err(fail)?
                        .expose_public()
                    {
                        return Err(fail("incorrect tag accepted"));
                    }
                }
                bytes.fill(0);
            }
        }};
    }
    macro_rules! xof {
        ($name:ident) => {{
            let mut state =
                api::$name::new_bits_conformance(selection.mode()?, key, custom).map_err(fail)?;
            selection.check_actual(state.report())?;
            for chunk in prefix.chunks(11) {
                state.update(chunk).map_err(fail)?;
                state.update(&[]).map_err(fail)?;
            }
            let mut reader = state.finalize_bits_xof_conformance(tail).map_err(fail)?;
            let split = expected.len().saturating_sub(1);
            let (first, last) = bytes.split_at_mut(split);
            let mut offset = 0;
            for (index, chunk) in first.chunks_mut(13).enumerate() {
                let end = offset + chunk.len();
                if index % 2 == 0 {
                    let secret = reader.squeeze_secret(chunk).map_err(fail)?;
                    if secret.expose() != &expected[offset..end] {
                        return Err(fail("incremental secret mismatch"));
                    }
                    drop(secret);
                    if chunk.iter().any(|b| *b != 0) {
                        return Err(fail("secret output Drop"));
                    }
                } else {
                    reader
                        .squeeze_public(chunk, KmacPublicDeclassification::acknowledge())
                        .map_err(fail)?;
                    if chunk != &expected[offset..end] {
                        return Err(fail("incremental public mismatch"));
                    }
                    chunk.fill(0);
                }
                offset = end;
            }
            let secret = reader
                .squeeze_final_bits_secret(last, valid)
                .map_err(fail)?;
            if secret.expose() != &expected[split..] {
                return Err(fail("partial secret output mismatch"));
            }
            drop(secret);
            if state.finalize_xof_conformance().is_ok() || state.update(&[]).is_ok() {
                return Err(fail("terminal owner reopened"));
            }
        }};
    }
    match algorithm {
        "kmac128" => fixed!(Kmac128),
        "kmac256" => fixed!(Kmac256),
        "kmacxof128" => xof!(KmacXof128),
        "kmacxof256" => xof!(KmacXof256),
        _ => return Err(fail("algorithm")),
    }
    if bytes.iter().any(|b| *b != 0) {
        return Err(fail("secret destination not cleared"));
    }
    Ok(())
}
