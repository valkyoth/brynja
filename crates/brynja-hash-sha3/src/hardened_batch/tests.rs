use super::*;
use crate::{Fips202BitString, Fips202Output};
extern crate std;
use std::{vec, vec::Vec};

const ALGORITHMS: [Algorithm; 8] = [
    Algorithm::Sha3_224,
    Algorithm::Sha3_256,
    Algorithm::Sha3_384,
    Algorithm::Sha3_512,
    Algorithm::Shake128,
    Algorithm::Shake256,
    Algorithm::Cshake128,
    Algorithm::Cshake256,
];
#[test]
fn accelerated_slot_mask_tracks_sparse_groups_not_selected_authority() -> Result<(), Error> {
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::Neon
    } else {
        Kernel::Avx2
    };
    if !kernel.compiled() {
        return Ok(());
    }
    let owner = Authority::for_compiled_target(kernel).map_err(Error::Backend)?;
    let executor =
        Executor::with_session(owner.session().map_err(Error::Backend)?, Mode::Prefer, 1)?;
    for active in 0_u8..16 {
        let mut inputs: [Option<Input<'_>>; CAPACITY] = core::array::from_fn(|_| None);
        for (index, slot) in inputs.iter_mut().enumerate() {
            if active & (1 << index) != 0 {
                *slot = Some(Input::new(Algorithm::Sha3_256, bits(b"abc", 24)?, 256)?);
            }
        }
        let count = usize::try_from(active.count_ones()).map_err(|_| Error::Invariant)?;
        let vector_count = count
            .checked_div(kernel.width())
            .and_then(|n| n.checked_mul(kernel.width()))
            .ok_or(Error::Invariant)?;
        let mut expected = 0_u8;
        let mut seen = 0_usize;
        for index in 0..CAPACITY {
            if active & (1 << index) != 0 && seen < vector_count {
                expected |= 1 << index;
                seen = seen.checked_add(1).ok_or(Error::Invariant)?;
            }
        }
        let mut outputs = [[0xa5; 32]; CAPACITY];
        let mut destinations = core::array::from_fn(|_| None);
        for (index, (output, destination)) in outputs.iter_mut().zip(&mut destinations).enumerate()
        {
            if active & (1 << index) != 0 {
                *destination = Some(output.as_mut_slice());
            }
        }
        let mut workspace = Workspace::new();
        let mut staging = [0xff; 128];
        let mut no = || false;
        let (secret, report) = executor.digest_secret(
            &inputs,
            destinations,
            &mut workspace,
            &mut staging,
            &mut Control::new(4, &mut no),
        )?;
        assert_eq!(report.accelerated_slots, expected);
        assert_eq!(report.vector_permutations, vector_count as u64);
        drop(secret);
        assert_eq!(staging, [0; 128]);
    }
    Ok(())
}
#[test]
fn input_identity_width_and_customization_are_checked() -> Result<(), Error> {
    let empty = bits(&[], 0)?;
    let custom = bits(&[1], 1)?;
    for algorithm in ALGORITHMS {
        let width = algorithm.fixed_output_bits().unwrap_or(0);
        let input = Input::new(algorithm, empty, width)?;
        assert_eq!(input.algorithm(), algorithm);
        assert_eq!(input.output_bits(), width);
        assert_eq!(input.output_bytes(), width.div_ceil(8));
        if algorithm.fixed_output_bits().is_some() {
            assert!(matches!(
                Input::new(algorithm, empty, width + 1),
                Err(Error::InvalidInput)
            ));
            assert!(matches!(
                Input::new(algorithm, empty, 0),
                Err(Error::InvalidInput)
            ));
        } else {
            assert_eq!(
                Input::new(algorithm, empty, usize::MAX)?.output_bytes(),
                usize::MAX.div_ceil(8)
            );
        }
        for (name, customization) in [(custom, empty), (empty, custom), (custom, custom)] {
            let result = Input::with_customization(algorithm, empty, name, customization, width);
            if algorithm.customized() {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(Error::InvalidInput)));
            }
        }
    }
    Ok(())
}
fn bits(bytes: &[u8], n: usize) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(
        bytes,
        if n == 0 {
            0
        } else {
            u8::try_from((n.saturating_sub(1) % 8).saturating_add(1))
                .map_err(|_| Error::Invariant)?
        },
    )
    .map_err(|_| Error::InvalidInput)
}
fn oracle(input: &Input<'_>) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; input.output_bytes()];
    let valid = if input.output_bits == 0 {
        0
    } else {
        u8::try_from((input.output_bits.saturating_sub(1) % 8).saturating_add(1))
            .map_err(|_| Error::Invariant)?
    };
    macro_rules! fixed {
        ($function:expr) => {
            out.copy_from_slice(
                $function(input.message)
                    .map_err(|_| Error::Invariant)?
                    .as_bytes(),
            )
        };
    }
    macro_rules! xof {
        ($function:expr) => {
            $function(
                input.message,
                Fips202Output::new(&mut out, valid).map_err(|_| Error::Invariant)?,
            )
            .map_err(|_| Error::Invariant)?
        };
    }
    macro_rules! custom {
        ($function:expr) => {
            $function(
                input.message,
                input.name,
                input.customization,
                Fips202Output::new(&mut out, valid).map_err(|_| Error::Invariant)?,
            )
            .map_err(|_| Error::Invariant)?
        };
    }
    match input.algorithm {
        Algorithm::Sha3_224 => fixed!(crate::sha3_224_bits),
        Algorithm::Sha3_256 => fixed!(crate::sha3_256_bits),
        Algorithm::Sha3_384 => fixed!(crate::sha3_384_bits),
        Algorithm::Sha3_512 => fixed!(crate::sha3_512_bits),
        Algorithm::Shake128 => xof!(crate::shake128_bits),
        Algorithm::Shake256 => xof!(crate::shake256_bits),
        Algorithm::Cshake128 => custom!(crate::cshake128_bits),
        Algorithm::Cshake256 => custom!(crate::cshake256_bits),
    }
    Ok(out)
}

fn cleared(s: &Workspace) -> bool {
    s.states
        .as_flattened()
        .iter()
        .chain(s.vector.as_flattened())
        .chain(s.starts.as_flattened())
        .chain(s.written.as_flattened())
        .chain(&s.ready)
        .chain(&s.eligible)
        .chain(&s.absorbing)
        .all(|v| *v == 0)
        && s.frames.iter().all(super::framing::Frame::is_cleared)
        && [
            &s.scalar.sponge_lanes[..],
            &s.scalar.partial_input[..],
            &s.scalar.message_length[..],
            &s.scalar.output_length[..],
            &s.scalar.cshake_setup_length[..],
            &s.scalar.cshake_domain[..],
            &s.scalar.phase[..],
            &s.scalar.suffix_staging[..],
            &s.scalar.padding_block[..],
            &s.scalar.squeeze_staging[..],
            &s.scalar.permutation_columns[..],
            &s.scalar.permutation_theta[..],
            &s.scalar.permutation_rearranged[..],
        ]
        .iter()
        .all(|region| region.iter().all(|v| *v == 0))
}
std::thread_local! { static DROPS: Cell<usize> = const { Cell::new(0) }; }
pub(super) fn observe_drop(s: &Workspace) {
    DROPS.with(|n| {
        n.set(if cleared(s) {
            n.get().saturating_add(1)
        } else {
            usize::MAX
        })
    });
}
fn destinations(outputs: &mut [Vec<u8>; CAPACITY]) -> [Option<&mut [u8]>; CAPACITY] {
    outputs.each_mut().map(|out| Some(out.as_mut_slice()))
}
fn campaign(executor: &Executor<'_>, vector: bool) -> Result<(), Error> {
    let mut workspace = Workspace::new();
    for case in 0_usize..128 {
        let mut identities = Vec::new();
        let mut lengths = Vec::new();
        let mut messages = Vec::new();
        for i in 0_usize..4 {
            let algorithm = *ALGORITHMS
                .get(case.saturating_add(i) % 8)
                .ok_or(Error::Invariant)?;
            let rate = algorithm.rate().saturating_mul(8);
            let boundaries = [
                0,
                1,
                7,
                8,
                rate.saturating_sub(5),
                rate.saturating_sub(3),
                rate.saturating_sub(1),
                rate,
                rate.saturating_add(1),
                rate.saturating_mul(2).saturating_add(7),
            ];
            let n = *boundaries
                .get(case.saturating_add(i) % 10)
                .ok_or(Error::Invariant)?;
            let mut message = vec![0xa3; n.div_ceil(8)];
            if !n.is_multiple_of(8)
                && let Some(last) = message.last_mut()
            {
                *last &= super::framing::mask(n % 8);
            }
            identities.push(algorithm);
            lengths.push(n);
            messages.push(message);
        }
        let mut inputs = Vec::new();
        for (i, ((algorithm, message), n)) in identities
            .into_iter()
            .zip(&messages)
            .zip(lengths)
            .enumerate()
        {
            let output_bits = algorithm.fixed_output_bits().unwrap_or(
                *[0, 1, 7, 8, 1089, 2701, 4096]
                    .get(case.saturating_add(i) % 7)
                    .ok_or(Error::Invariant)?,
            );
            let (name, custom) = if algorithm.customized() && case % 3 != 0 {
                (bits(&[0x15], 5)?, bits(&[0x25, 1], 9)?)
            } else {
                (bits(&[], 0)?, bits(&[], 0)?)
            };
            inputs.push(Input::with_customization(
                algorithm,
                bits(message, n)?,
                name,
                custom,
                output_bits,
            )?);
        }
        if case % 2 == 0 {
            inputs.reverse();
        }
        let expected: Vec<_> = inputs.iter().map(oracle).collect::<Result<_, _>>()?;
        // Every byte starts guaranteed incorrect, catching stale/no-op output.
        let actual: Vec<Vec<u8>> = expected
            .iter()
            .map(|o| o.iter().map(|b| !b).collect())
            .collect();

        let inputs: [Option<Input<'_>>; CAPACITY] = inputs
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::Invariant)?;
        let mut actual: [Vec<u8>; CAPACITY] = actual.try_into().map_err(|_| Error::Invariant)?;
        let mut staging = vec![
            0x71;
            expected
                .iter()
                .map(Vec::len)
                .sum::<usize>()
                .saturating_add(17)
        ];
        let mut cancel = || false;
        let mut control = Control::new(1024, &mut cancel);
        let before = executor
            .session
            .as_ref()
            .map_or(0, Session::completed_vector_calls);
        let (owner, report) = executor.digest_secret(
            &inputs,
            destinations(&mut actual),
            &mut workspace,
            &mut staging,
            &mut control,
        )?;
        for (i, (expected, input)) in expected.iter().zip(&inputs).enumerate() {
            assert_eq!(owner.expose(i), Some(expected.as_slice()));
            let input = input.as_ref().ok_or(Error::Invariant)?;
            assert_eq!(owner.algorithm(i), Some(input.algorithm()));
            assert_eq!(owner.output_bits(i), Some(input.output_bits()));
        }
        drop(owner);
        assert!(actual.iter().all(|out| out.iter().all(|v| *v == 0)));
        assert!(staging.iter().all(|v| *v == 0));
        assert!(cleared(&workspace));
        let after = executor
            .session
            .as_ref()
            .map_or(0, Session::completed_vector_calls);
        assert_eq!(after.checked_sub(before), Some(report.vector_calls));
        assert_eq!(
            report
                .vector_permutations
                .checked_add(report.scalar_permutations),
            Some(control.used())
        );
        assert_eq!(report.vector_calls != 0, vector);
        assert_eq!(report.accelerated_slots, if vector { 0b1111 } else { 0 });
        let mut cancel = || false;
        let mut control = Control::new(1024, &mut cancel);
        executor.digest_public(
            &inputs,
            destinations(&mut actual),
            &mut workspace,
            &mut staging,
            &mut control,
            Sha3PublicDeclassification::acknowledge(),
        )?;
        assert_eq!(actual.as_slice(), expected.as_slice());
        assert!(cleared(&workspace));
        assert!(staging.iter().all(|v| *v == 0));
    }
    Ok(())
}

#[test]
fn portable_mixed_domains_bit_tails_and_squeeze_boundaries() -> Result<(), Error> {
    campaign(&Executor::portable(), false)
}
#[test]
fn native_differential_uses_hardened_vector_authority() -> Result<(), Error> {
    let mut executed = false;
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        executed = true;
        let owner = Authority::for_compiled_target(kernel).map_err(Error::Backend)?;
        let executor =
            Executor::with_session(owner.session().map_err(Error::Backend)?, Mode::Require, 1)?;
        campaign(&executor, true)?;
    }
    if std::env::var_os("BRYNJA_REQUIRE_HARDENED_KECCAK_LEAF").is_some() {
        assert!(executed);
    }
    Ok(())
}
mod lifecycle;
mod output;
