use super::*;
use crate::{BitString, Md5Batch, Md5BatchControl, owner::Md5Owner};

fn session() -> Option<Md5BackendSession> {
    compiled_backend()?;
    let result = Md5BackendSession::for_compiled_target();
    if !cfg!(all(feature = "cpu-evidence", brynja_md5_cpu_evidence)) {
        assert_eq!(result.err(), Some(Md5BackendError::NotAdmitted));
        return None;
    }
    assert!(result.is_ok());
    let result = result.ok()?;
    assert_eq!(result.health(), Md5BackendHealth::Healthy);
    Some(result)
}

#[test]
fn identities_and_admission() {
    assert_eq!(Md5Backend::X86Avx2.lane_width(), 8);
    assert_eq!(Md5Backend::Aarch64Neon.lane_width(), 4);
    assert!(!Md5Backend::X86Avx2.is_admitted());
    assert!(!Md5Backend::Aarch64Neon.is_admitted());
    let _ = session();
}

#[test]
fn independent_arbitrary_state_block_lanes_match_frozen_scalar() {
    let Some(session) = session() else { return };
    let mut rng = 0x9e3779b9_u32;
    for _ in 0..2048 {
        let mut owners: [Md5Owner; 8] = core::array::from_fn(|_| Md5Owner::new());
        let mut states = [[0_u32; 4]; 8];
        let mut blocks = [[0_u8; 64]; 8];
        for ((owner, state), block) in owners.iter_mut().zip(&mut states).zip(&mut blocks) {
            for byte in owner
                .chaining_state
                .iter_mut()
                .chain(owner.block.iter_mut())
            {
                rng ^= rng << 13;
                rng ^= rng >> 17;
                rng ^= rng << 5;
                *byte = rng.to_le_bytes().first().copied().unwrap_or(0);
            }
            for (word, bytes) in state
                .iter_mut()
                .zip(owner.chaining_state.as_chunks::<4>().0.iter())
            {
                let [a, b, c, d] = bytes;
                *word = u32::from_le_bytes([*a, *b, *c, *d]);
            }
            *block = owner.block;
        }
        let before = states;
        assert_eq!(session.compress(&mut states, &blocks), Ok(()));
        for (i, ((owner, state), old)) in owners.iter_mut().zip(states).zip(before).enumerate() {
            if i < session.backend().lane_width() {
                crate::compress::compress(owner);
                for (word, bytes) in state
                    .into_iter()
                    .zip(owner.chaining_state.as_chunks::<4>().0.iter())
                {
                    assert_eq!(word.to_le_bytes(), *bytes);
                }
            } else {
                assert_eq!(state, old);
            }
        }
    }
}

#[test]
fn masks_lengths_and_bit_tails_preserve_lane_order() {
    let Some(session) = session() else { return };
    let data: [[u8; 257]; 8] =
        core::array::from_fn(|i| [u8::try_from(i).unwrap_or(0).saturating_mul(32); 257]);
    for mask in [0_u16, 1, 15, 85, 127, 128, 240, 254, 255] {
        for length in [0_usize, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 255] {
            for valid in 1..=8 {
                let inputs = core::array::from_fn(|i| {
                    if mask & (1 << i) == 0 {
                        return None;
                    }
                    let used = length.saturating_add(i % 3).min(257);
                    let bytes = data.get(i).and_then(|d| d.get(..used)).unwrap_or_default();
                    let bits = BitString::new(bytes, if used == 0 { 0 } else { valid });
                    // The input byte pattern has only its upper three bits set.
                    // Canonicalize narrower tails in a separate corpus; here
                    // reject invalid widths rather than skip an execution fault.
                    bits.ok()
                });
                let mut expected = [[0xa5; 16]; 8];
                let mut actual = expected;
                assert!(
                    Md5Batch::new()
                        .digest(&inputs, &mut expected, &mut Md5BatchControl::new(64))
                        .is_ok()
                );
                let report = Md5Batch::new().digest_with_backend(
                    &inputs,
                    &mut actual,
                    &mut Md5BatchControl::new(64),
                    &session,
                );
                assert!(report.is_ok());
                assert_eq!(actual, expected);
                if mask == 255 && length >= 65 && valid >= 3 {
                    assert!(report.is_ok_and(|r| r.vector_blocks >= 8));
                }
            }
        }
    }
}

#[test]
fn failed_kat_and_lost_features_are_permanent_and_atomic() {
    let Some(mut session) = session() else { return };
    let bad = Md5BackendSession::construct(session.backend(), compiled_features, true);
    assert!(bad.is_ok());
    if let Ok(bad) = bad {
        assert_eq!(bad.health(), Md5BackendHealth::Quarantined);
    }
    session.revalidate = |_| false;
    let mut state = [[0xa5; 4]; 8];
    assert_eq!(
        session.compress(&mut state, &[[0; 64]; 8]),
        Err(Md5BackendError::MissingFeatures)
    );
    session.revalidate = compiled_features;
    assert_eq!(
        session.compress(&mut state, &[[0; 64]; 8]),
        Err(Md5BackendError::Quarantined)
    );
    assert_eq!(state, [[0xa5; 4]; 8]);
}

#[test]
fn every_accelerated_cancellation_and_late_quarantine_preserves_output() {
    let Some(session) = session() else { return };
    let message = [0_u8; 256];
    let bits = BitString::new(&message, 8);
    assert!(bits.is_ok());
    let inputs = [bits.ok(); 8];
    // Count every callback on a successful execution, then inject a failure
    // at each exact checkpoint, including the final pre-commit checkpoint.
    let mut calls = 0_usize;
    let mut callback = || {
        calls = calls.saturating_add(1);
        false
    };
    let mut output = [[0; 16]; 8];
    assert!(
        Md5Batch::new()
            .digest_with_backend(
                &inputs,
                &mut output,
                &mut Md5BatchControl::with_cancellation(40, &mut callback),
                &session
            )
            .is_ok()
    );
    for stop in 0..calls {
        let mut count = 0_usize;
        let mut callback = || {
            let result = count == stop;
            count = count.saturating_add(1);
            result
        };
        output = [[0xa5; 16]; 8];
        assert_eq!(
            Md5Batch::new().digest_with_backend(
                &inputs,
                &mut output,
                &mut Md5BatchControl::with_cancellation(40, &mut callback),
                &session
            ),
            Err(crate::Md5BatchError::Cancelled)
        );
        assert_eq!(output, [[0xa5; 16]; 8]);
    }
    for budget in 0..40 {
        output = [[0xa5; 16]; 8];
        assert_eq!(
            Md5Batch::new().digest_with_backend(
                &inputs,
                &mut output,
                &mut Md5BatchControl::new(budget),
                &session
            ),
            Err(crate::Md5BatchError::WorkLimit)
        );
        assert_eq!(output, [[0xa5; 16]; 8]);
    }
    let mut count = 0_usize;
    let mut callback = || {
        count = count.saturating_add(1);
        if count == calls {
            session.healthy.set(false);
        }
        false
    };
    output = [[0xa5; 16]; 8];
    assert_eq!(
        Md5Batch::new().digest_with_backend(
            &inputs,
            &mut output,
            &mut Md5BatchControl::with_cancellation(40, &mut callback),
            &session
        ),
        Err(crate::Md5BatchError::Backend)
    );
    assert_eq!(output, [[0xa5; 16]; 8]);
}
