use super::{CshakeLifecycle, HardenedCshake128, HardenedCshake256};
use crate::{
    Fips202BitString, Fips202Output,
    hardened::{HardenedSha3Error, Sha3PublicDeclassification, owner::HardenedFips202Owner},
};

fn is_cleared<const RATE: usize>(owner: &HardenedFips202Owner<RATE>) -> bool {
    owner.sponge_lanes.iter().all(|byte| *byte == 0)
        && owner.partial_input.iter().all(|byte| *byte == 0)
        && owner.message_length.iter().all(|byte| *byte == 0)
        && owner.output_length.iter().all(|byte| *byte == 0)
        && owner.cshake_setup_length.iter().all(|byte| *byte == 0)
        && owner.cshake_domain.iter().all(|byte| *byte == 0)
        && owner.phase.iter().all(|byte| *byte == 0)
        && owner.suffix_staging.iter().all(|byte| *byte == 0)
        && owner.padding_block.iter().all(|byte| *byte == 0)
        && owner.squeeze_staging.iter().all(|byte| *byte == 0)
        && owner.permutation_columns.iter().all(|byte| *byte == 0)
        && owner.permutation_theta.iter().all(|byte| *byte == 0)
        && owner.permutation_rearranged.iter().all(|byte| *byte == 0)
}

#[test]
fn in_place_reader_transition_clears_exact_source_owner() {
    let cshake128 = HardenedCshake128::new(b"KMAC", b"source wipe");
    assert!(cshake128.is_ok());
    let Ok(mut cshake128) = cshake128 else { return };
    assert_eq!(cshake128.update(b"secret-derived state"), Ok(()));
    let reader128 = cshake128.finalize_xof_erasing_source();
    assert!(reader128.is_ok());
    let Ok(reader128) = reader128 else { return };
    assert!(is_cleared(&cshake128.owner));
    assert!(cshake128.lifecycle == CshakeLifecycle::Vacated);
    assert_eq!(
        cshake128.check_additional_bytes(0),
        Err(HardenedSha3Error::StateConsumed)
    );
    assert_eq!(
        cshake128.check_additional_bits(0),
        Err(HardenedSha3Error::StateConsumed)
    );
    assert_eq!(
        cshake128.update(b"second"),
        Err(HardenedSha3Error::StateConsumed)
    );
    assert!(matches!(
        cshake128.finalize_xof_erasing_source(),
        Err(HardenedSha3Error::StateConsumed)
    ));
    reader128.cancel();

    let cshake256 = HardenedCshake256::new(b"KMAC", b"source wipe");
    assert!(cshake256.is_ok());
    let Ok(mut cshake256) = cshake256 else { return };
    let tail = Fips202BitString::new(&[0b0000_0101], 3);
    assert!(tail.is_ok());
    let Ok(tail) = tail else { return };
    let reader256 = cshake256.finalize_bits_xof_erasing_source(tail);
    assert!(reader256.is_ok());
    let Ok(reader256) = reader256 else { return };
    assert!(is_cleared(&cshake256.owner));
    assert!(cshake256.lifecycle == CshakeLifecycle::Vacated);
    assert_eq!(
        cshake256.update(b"second"),
        Err(HardenedSha3Error::StateConsumed)
    );
    assert!(matches!(
        cshake256.finalize_bits_xof_erasing_source(tail),
        Err(HardenedSha3Error::StateConsumed)
    ));
    reader256.cancel();
}

#[test]
fn explicit_wipe_is_an_irreversible_terminal_transition() {
    let cshake128 = HardenedCshake128::new(b"KMAC", b"explicit wipe");
    assert!(cshake128.is_ok());
    let Ok(mut cshake128) = cshake128 else { return };
    assert_eq!(cshake128.update(b"secret-derived state"), Ok(()));
    cshake128.wipe_in_place();
    assert!(is_cleared(&cshake128.owner));
    assert!(cshake128.lifecycle == CshakeLifecycle::Vacated);
    assert_eq!(
        cshake128.update(b"second"),
        Err(HardenedSha3Error::StateConsumed)
    );
    assert!(matches!(
        cshake128.finalize_xof_erasing_source(),
        Err(HardenedSha3Error::StateConsumed)
    ));

    let cshake256 = HardenedCshake256::new(b"KMAC", b"explicit wipe");
    assert!(cshake256.is_ok());
    let Ok(mut cshake256) = cshake256 else { return };
    cshake256.wipe_in_place();
    assert!(is_cleared(&cshake256.owner));
    assert!(cshake256.lifecycle == CshakeLifecycle::Vacated);
    assert_eq!(
        cshake256.check_additional_bytes(1),
        Err(HardenedSha3Error::StateConsumed)
    );
    assert!(matches!(
        cshake256.finalize_xof_erasing_source(),
        Err(HardenedSha3Error::StateConsumed)
    ));
}

#[test]
fn final_bit_output_clears_the_exact_reader_source() {
    let state = HardenedCshake128::new(b"TupleHash", b"reader wipe");
    assert!(state.is_ok());
    let Ok(mut state) = state else { return };
    assert_eq!(state.update(b"secret-derived state"), Ok(()));
    let reader = state.finalize_xof_erasing_source();
    assert!(reader.is_ok());
    let Ok(mut reader) = reader else { return };
    let mut public_bytes: [u8; 3] = Default::default();
    let output = Fips202Output::new(&mut public_bytes, 5);
    assert!(output.is_ok());
    let Ok(output) = output else { return };
    assert_eq!(
        reader.squeeze_final_bits_public_erasing_source(
            output,
            Sha3PublicDeclassification::acknowledge(),
        ),
        Ok(())
    );
    assert!(is_cleared(&reader.owner));
    assert!(reader.lifecycle == CshakeLifecycle::Vacated);
    assert_eq!(
        reader.check_additional_bits(1),
        Err(HardenedSha3Error::StateConsumed)
    );

    let state = HardenedCshake256::new(b"TupleHash", b"reader wipe");
    assert!(state.is_ok());
    let Ok(mut state) = state else { return };
    assert_eq!(state.update(b"secret-derived state"), Ok(()));
    let reader = state.finalize_xof_erasing_source();
    assert!(reader.is_ok());
    let Ok(mut reader) = reader else { return };
    let mut secret_bytes: [u8; 3] = Default::default();
    let output = Fips202Output::new(&mut secret_bytes, 5);
    assert!(output.is_ok());
    let Ok(output) = output else { return };
    let secret = reader.squeeze_final_bits_secret_erasing_source(output);
    assert!(secret.is_ok());
    assert!(is_cleared(&reader.owner));
    assert!(reader.lifecycle == CshakeLifecycle::Vacated);
    assert_eq!(
        reader.check_additional_bytes(1),
        Err(HardenedSha3Error::StateConsumed)
    );
    drop(secret);
    assert!(secret_bytes.iter().all(|byte| *byte == 0));
}
