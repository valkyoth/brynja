use super::*;
use crate::Sha512TBits;

fn campaign(executor: &Executor<'_>, accelerated: bool) -> Result<(), Error> {
    for t in 1..512 {
        if t == 384 {
            continue;
        }
        let parameter = Sha512TBits::new(t).map_err(|_| Error::Invariant)?;
        let identities = [
            Algorithm::Sha512_224,
            Algorithm::Sha512_256,
            Algorithm::Sha512T(parameter),
            Algorithm::Sha512T(Sha512TBits::new(9).map_err(|_| Error::Invariant)?),
        ];
        for (length, tail) in [(111_usize, 1), (129, 3), (256, 7)] {
            let mut message = [0x91; 256];
            let message = message.get_mut(..length).ok_or(Error::Invariant)?;
            *message.last_mut().ok_or(Error::Invariant)? &= u8::MAX << 8_u8.saturating_sub(tail);
            let b = bits(message, tail)?;
            let inputs = identities.map(|algorithm| Some(Input::new(algorithm, b)));
            let mut bytes = [[0xa5; 64]; CAPACITY];
            let mut workspace = Workspace::new();
            let mut cancel = || false;
            let mut control = Control::new(100, &mut cancel);
            let (owner, report) = executor.digest_secret(
                &inputs,
                destinations(&mut bytes, &inputs),
                &mut workspace,
                &mut control,
            )?;
            for (index, input) in inputs.iter().enumerate() {
                let input = input.as_ref().ok_or(Error::Invariant)?;
                let expected = oracle(input)?;
                assert_eq!(owner.algorithm(index), Some(input.algorithm));
                assert_eq!(
                    owner.expose(index),
                    Some(
                        expected
                            .get(..input.algorithm.output_bytes())
                            .ok_or(Error::Invariant)?
                    )
                );
            }
            if accelerated && length >= 129 {
                assert!(report.vector_calls > 0);
            }
            // Two public general-t IV derivations plus complete input/padding work.
            let (complete, _) = b.split();
            let padding = if complete.len() % 128 >= 112 { 2 } else { 1 };
            let blocks = complete
                .len()
                .checked_div(128)
                .and_then(|n| n.checked_add(padding))
                .and_then(|n| n.checked_mul(CAPACITY))
                .and_then(|n| n.checked_add(2))
                .ok_or(Error::Invariant)?;
            assert_eq!(
                control.used(),
                u64::try_from(blocks).map_err(|_| Error::Invariant)?
            );
            assert_eq!(
                report.vector_blocks.checked_add(report.scalar_blocks),
                Some(control.used())
            );
            drop(owner);
            for (slot, identity) in bytes.iter().zip(identities) {
                assert!(
                    slot.get(..identity.output_bytes())
                        .ok_or(Error::Invariant)?
                        .iter()
                        .all(|byte| *byte == 0)
                );
                assert!(
                    slot.get(identity.output_bytes()..)
                        .ok_or(Error::Invariant)?
                        .iter()
                        .all(|byte| *byte == 0xa5)
                );
            }
            cleared(&workspace);
        }
    }
    Ok(())
}
#[test]
fn all_parameters_preserve_identity_and_canonical_secret_output() -> Result<(), Error> {
    campaign(&Executor::portable(), false)?;
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let authority = Authority::for_compiled_target(kernel).map_err(Error::Backend)?;
        let executor = Executor::with_session(
            authority.session().map_err(Error::Backend)?,
            Mode::Prefer,
            1,
        )?;
        campaign(&executor, true)?;
    }
    Ok(())
}
#[test]
fn parameter_identity_codes_are_injective_and_invalid_codes_rejected() -> Result<(), Error> {
    for code in 0..=u16::MAX {
        let algorithm = Algorithm::from_code(code);
        let valid = matches!(code, 1..=4 | 0x1001..=0x117f | 0x1181..=0x11ff);
        assert_eq!(algorithm.is_some(), valid);
        if let Some(algorithm) = algorithm {
            assert_eq!(algorithm.code(), code);
        }
    }
    for (named, t) in [(Algorithm::Sha512_224, 224), (Algorithm::Sha512_256, 256)] {
        let general = Algorithm::Sha512T(Sha512TBits::new(t).map_err(|_| Error::Invariant)?);
        assert_ne!(named, general);
        assert_eq!(named.initial_words(), general.initial_words());
    }
    Ok(())
}
#[test]
fn iv_derivation_is_charged_and_required_rejection_precedes_hashing() -> Result<(), Error> {
    let algorithm = Algorithm::Sha512T(Sha512TBits::new(9).map_err(|_| Error::Invariant)?);
    let b = bits(b"abc", 8)?;
    let inputs = core::array::from_fn(|_| Some(Input::new(algorithm, b)));
    let executor = Executor::portable();
    for budget in 0..8 {
        let mut bytes = [[0xa5; 64]; CAPACITY];
        let mut workspace = Workspace::new();
        let mut cancel = || false;
        let mut control = Control::new(budget, &mut cancel);
        assert!(matches!(
            executor.digest_secret(
                &inputs,
                destinations(&mut bytes, &inputs),
                &mut workspace,
                &mut control
            ),
            Err(Error::WorkLimit)
        ));
        for out in bytes {
            assert_eq!(out.get(..2), Some([0, 0].as_slice()));
        }
        assert_eq!(control.used(), budget);
        cleared(&workspace);
        reusable(&executor)?;
    }
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let authority = Authority::for_compiled_target(kernel).map_err(Error::Backend)?;
        let executor = Executor::with_session(
            authority.session().map_err(Error::Backend)?,
            Mode::Require,
            1,
        )?;
        let mut bytes = [[0xa5; 64]; CAPACITY];
        let mut workspace = Workspace::new();
        let mut cancel = || false;
        let mut control = Control::new(0, &mut cancel);
        assert!(matches!(
            executor.digest_secret(
                &inputs,
                destinations(&mut bytes, &inputs),
                &mut workspace,
                &mut control
            ),
            Err(Error::IneligibleWorkload)
        ));
        assert_eq!(control.used(), 0);
        assert_eq!(
            authority
                .session()
                .map_err(Error::Backend)?
                .completed_vector_calls(),
            0
        );
        reusable(&executor)?;
        cleared(&workspace);
    }
    Ok(())
}
