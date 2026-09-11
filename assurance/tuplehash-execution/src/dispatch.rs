use crate::{bit_string, selection::Selection, valid_bits};
use brynja_hash_tuple::{
    Fips202BitString, TupleHashPublicDeclassification as Public, execution as api,
};
use std::io;

fn invalid(error: impl core::fmt::Debug) -> io::Error {
    io::Error::other(format!("TupleHash execution: {error:?}"))
}

pub fn run(
    algorithm: &str,
    custom: Fips202BitString<'_>,
    items: &[(Vec<u8>, usize)],
    output_bits: usize,
    output: &mut [u8],
    selection: &Selection,
) -> Result<(), io::Error> {
    let valid = valid_bits(output_bits);
    let mut scratch = [0x5a; 512];
    let mut secret_bytes = [0xa5; 512];
    let secret_bytes = secret_bytes
        .get_mut(..output.len())
        .ok_or_else(|| invalid("output bound"))?;
    macro_rules! ordinary {
        ($name:ident) => {{
            let mut state = api::$name::new_bits(selection.mode()?, custom).map_err(invalid)?;
            selection.check_actual(state.report())?;
            for (bytes, bits) in items {
                state
                    .push_item_bits(bit_string(bytes, *bits, 0)?)
                    .map_err(invalid)?;
            }
            selection.check_actual(state.report())?;
            state
        }};
    }
    // The hardened owner receives each exact item via a different partitioning:
    // bounded byte fragments followed by its canonical fractional tail.
    macro_rules! hardened {
        ($name:ident) => {{
            let mut state = api::$name::new_bits(selection.mode()?, custom).map_err(invalid)?;
            selection.check_actual(state.report())?;
            for (bytes, bits) in items {
                let mut writer = state
                    .begin_item(u128::try_from(*bits).map_err(invalid)?)
                    .map_err(invalid)?;
                selection.check_actual(writer.report())?;
                let complete = bits / 8;
                for chunk in bytes
                    .get(..complete)
                    .ok_or_else(|| invalid("item bound"))?
                    .chunks(23)
                {
                    writer.update(&[]).map_err(invalid)?;
                    writer.update(chunk).map_err(invalid)?;
                }
                if !bits.is_multiple_of(8) {
                    writer
                        .update_bits(bit_string(
                            bytes.get(complete..).ok_or_else(|| invalid("tail bound"))?,
                            bits % 8,
                            0,
                        )?)
                        .map_err(invalid)?;
                }
                if writer.remaining_bits() != 0 {
                    return Err(invalid("inexact item accounting"));
                }
                writer.finish().map_err(invalid)?;
            }
            if state.item_count() != u128::try_from(items.len()).map_err(invalid)? {
                return Err(invalid("item count differs"));
            }
            state
        }};
    }
    macro_rules! fixed {
        ($ordinary:ident, $hardened:ident) => {{
            ordinary!($ordinary)
                .finalize_bits(output, valid, &mut scratch)
                .map_err(invalid)?;
            if scratch != [0; 512] {
                return Err(invalid("public scratch retained data"));
            }
            let secret = hardened!($hardened)
                .finalize_secret_bits(secret_bytes, valid)
                .map_err(invalid)?;
            if secret.expose() != output {
                return Err(invalid("secret/public fixed disagreement"));
            }
            drop(secret);
            if secret_bytes.iter().any(|byte| *byte != 0) {
                return Err(invalid("secret output not cleared"));
            }
            secret_bytes.fill(0xa5);
            hardened!($hardened)
                .finalize_public_bits(secret_bytes, valid, &mut scratch, Public::acknowledge())
                .map_err(invalid)?;
            if secret_bytes != output {
                return Err(invalid("declassified fixed disagreement"));
            }
        }};
    }
    macro_rules! xof {
        ($ordinary:ident, $hardened:ident) => {{
            let mut state = ordinary!($ordinary);
            let reader = state.finalize_xof().map_err(invalid)?;
            selection.check_actual(reader.report())?;
            reader
                .squeeze_final_bits(output, valid, &mut scratch)
                .map_err(invalid)?;
            if scratch != [0; 512] {
                return Err(invalid("XOF scratch retained data"));
            }
            let mut state = hardened!($hardened);
            let mut reader = state.finalize_xof().map_err(invalid)?;
            selection.check_actual(reader.report())?;
            let split = output.len().saturating_sub(1).min(17);
            let (prefix, tail) = secret_bytes.split_at_mut(split);
            reader
                .squeeze_public_with_scratch(prefix, &mut scratch, Public::acknowledge())
                .map_err(invalid)?;
            let (expected_prefix, expected_tail) = output.split_at(split);
            if prefix != expected_prefix {
                return Err(invalid("XOF partition prefix differs"));
            }
            let secret = reader
                .squeeze_final_bits_secret(tail, valid)
                .map_err(invalid)?;
            if secret.expose() != expected_tail {
                return Err(invalid("secret/public XOF disagreement"));
            }
            drop(secret);
            if tail.iter().any(|byte| *byte != 0) {
                return Err(invalid("XOF secret output not cleared"));
            }
            if state.push_item(b"after-finalization").is_ok() {
                return Err(invalid("XOF source reopened"));
            }
        }};
    }
    match algorithm {
        "tuple128" => fixed!(TupleHash128, HardenedTupleHash128),
        "tuple256" => fixed!(TupleHash256, HardenedTupleHash256),
        "tuplexof128" => xof!(TupleHashXof128, HardenedTupleHashXof128),
        "tuplexof256" => xof!(TupleHashXof256, HardenedTupleHashXof256),
        _ => return Err(invalid("unknown algorithm")),
    }
    Ok(())
}
