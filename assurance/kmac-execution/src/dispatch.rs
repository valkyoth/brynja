use crate::selection::Selection;
use brynja_mac_kmac::{Fips202BitString, KmacPublicDeclassification, execution as api};
use std::io;

pub fn dispatch(
    algorithm: &str,
    key: Fips202BitString<'_>,
    custom: Fips202BitString<'_>,
    message: Fips202BitString<'_>,
    output_bits: usize,
    output: &mut [u8],
    selection: &Selection,
) -> Result<(), io::Error> {
    let valid = super::valid_bits(output_bits);
    // Bounded by the stdin campaign's 4095-bit maximum; no input-sized stack allocation.
    let mut scratch = [0_u8; 512];
    let failure = |error| io::Error::other(format!("KMAC execution rejected input: {error:?}"));
    match algorithm {
        "kmac128" => {
            let state = api::Kmac128::new_bits_conformance(selection.mode()?, key, custom)
                .map_err(failure)?;
            selection.check_actual(state.report())?;
            let _tag = state
                .finalize_tag_bits_conformance(message, output, valid, &mut scratch)
                .map_err(failure)?;
        }
        "kmac256" => {
            let state = api::Kmac256::new_bits_conformance(selection.mode()?, key, custom)
                .map_err(failure)?;
            selection.check_actual(state.report())?;
            let _tag = state
                .finalize_tag_bits_conformance(message, output, valid, &mut scratch)
                .map_err(failure)?;
        }
        "kmacxof128" => {
            let mut state = api::KmacXof128::new_bits_conformance(selection.mode()?, key, custom)
                .map_err(failure)?;
            selection.check_actual(state.report())?;
            state
                .finalize_bits_xof_conformance(message)
                .map_err(failure)?
                .squeeze_final_bits_public(
                    output,
                    valid,
                    &mut scratch,
                    KmacPublicDeclassification::acknowledge(),
                )
                .map_err(failure)?;
        }
        "kmacxof256" => {
            let mut state = api::KmacXof256::new_bits_conformance(selection.mode()?, key, custom)
                .map_err(failure)?;
            selection.check_actual(state.report())?;
            state
                .finalize_bits_xof_conformance(message)
                .map_err(failure)?
                .squeeze_final_bits_public(
                    output,
                    valid,
                    &mut scratch,
                    KmacPublicDeclassification::acknowledge(),
                )
                .map_err(failure)?;
        }
        _ => return Err(io::Error::other("unknown algorithm")),
    }
    if scratch != [0; 512] {
        return Err(io::Error::other("scratch not cleared"));
    }
    Ok(())
}
