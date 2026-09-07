extern crate std;
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn bits(bytes: &[u8], valid: u8) -> Option<BitString<'_>> {
    let value = BitString::new(bytes, valid);
    assert!(value.is_ok());
    value.ok()
}

#[test]
fn every_active_mask_and_uneven_bit_tail_matches_scalar() {
    let data: [[u8; 130]; 8] =
        core::array::from_fn(|i| [u8::try_from(i).unwrap_or(0).saturating_mul(32); 130]);
    for mask in 0..256_u16 {
        let inputs = core::array::from_fn(|i| {
            if mask & (1 << i) == 0 {
                None
            } else {
                let length = [0, 1, 55, 56, 63, 64, 65, 130].get(i).copied().unwrap_or(0);
                let bytes = data
                    .get(i)
                    .and_then(|d| d.get(..length))
                    .unwrap_or_default();
                bits(bytes, if length == 0 { 0 } else { 3 })
            }
        });
        let mut output = [[0xa5; 16]; 8];
        let report = Md5Batch::new().digest(&inputs, &mut output, &mut Md5BatchControl::new(32));
        assert!(report.is_ok());
        for (actual, input) in output.iter().zip(inputs) {
            assert_eq!(
                Ok(*actual),
                input.map(crate::md5_bits).unwrap_or(Ok([0; 16]))
            );
        }
        let mut hardened = [[0xa5; 16]; 8];
        let result = HardenedMd5Batch::new().digest_secret(
            &inputs,
            &mut hardened,
            &mut Md5BatchControl::new(32),
        );
        assert!(result.is_ok());
        if let Ok((secret, accounting)) = &result {
            assert_eq!(secret.expose(), output.as_flattened());
            assert_eq!(Ok(*accounting), report);
        }
        drop(result);
        assert_eq!(hardened, [[0; 16]; 8]);
    }
}

#[test]
fn exact_work_limits_and_every_callback_failure_are_transactional() {
    let message = [0_u8; 120];
    let inputs = [bits(&message, 8); 8];
    for limit in 0..24 {
        let mut output = [[0xa5; 16]; 8];
        assert_eq!(
            Md5Batch::new().digest(&inputs, &mut output, &mut Md5BatchControl::new(limit)),
            Err(Md5BatchError::WorkLimit)
        );
        assert_eq!(output, [[0xa5; 16]; 8]);
        let result = HardenedMd5Batch::new().digest_secret(
            &inputs,
            &mut output,
            &mut Md5BatchControl::new(limit),
        );
        assert!(matches!(result, Err(Md5BatchError::WorkLimit)));
        drop(result);
        assert_eq!(output, [[0; 16]; 8]);
    }
    for stop in 0..26 {
        let mut calls = 0_usize;
        let mut cancelled = || {
            let result = calls == stop;
            calls = calls.saturating_add(1);
            result
        };
        let mut output = [[0xa5; 16]; 8];
        assert_eq!(
            Md5Batch::new().digest(
                &inputs,
                &mut output,
                &mut Md5BatchControl::with_cancellation(24, &mut cancelled)
            ),
            Err(Md5BatchError::Cancelled)
        );
        assert_eq!(output, [[0xa5; 16]; 8]);
    }
    let mut output = [[0; 16]; 8];
    let mut control = Md5BatchControl::new(24);
    assert!(
        Md5Batch::new()
            .digest(&inputs, &mut output, &mut control)
            .is_ok()
    );
    assert_eq!(control.remaining(), 0);
}

#[test]
fn unwind_clears_secret_destination_and_preserves_public_destination() {
    let inputs = [bits(b"abc", 8); 8];
    for stop in 0..10 {
        for secret in [false, true] {
            let mut output = [[0xa5; 16]; 8];
            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut count = 0_usize;
                let mut callback = || {
                    assert_ne!(count, stop, "injected unwind");
                    count = count.saturating_add(1);
                    false
                };
                let mut control = Md5BatchControl::with_cancellation(8, &mut callback);
                if secret {
                    let _ =
                        HardenedMd5Batch::new().digest_secret(&inputs, &mut output, &mut control);
                } else {
                    let _ = Md5Batch::new().digest(&inputs, &mut output, &mut control);
                }
            }));
            assert!(result.is_err());
            assert_eq!(
                output,
                if secret {
                    [[0; 16]; 8]
                } else {
                    [[0xa5; 16]; 8]
                }
            );
        }
    }
}

#[test]
fn all_inactive_and_active_empty_are_distinct() {
    let mut output = [[0xa5; 16]; 8];
    assert_eq!(
        Md5Batch::new().digest(&[None; 8], &mut output, &mut Md5BatchControl::new(0)),
        Ok(Md5BatchReport::default())
    );
    assert_eq!(output, [[0; 16]; 8]);
    assert!(
        Md5Batch::new()
            .digest(
                &[bits(&[], 0); 8],
                &mut output,
                &mut Md5BatchControl::new(8)
            )
            .is_ok()
    );
    for digest in output {
        assert_eq!(Ok(digest), crate::md5(&[]));
    }
}

#[cfg(feature = "cpu")]
#[test]
fn quarantined_session_preserves_every_output_slot_even_when_inactive() {
    let session = crate::Md5BackendSession::quarantined_model_for_test();
    let mut output = [[0xa5; 16]; 8];
    assert_eq!(
        Md5Batch::new().digest_with_backend(
            &[None; 8],
            &mut output,
            &mut Md5BatchControl::new(0),
            &session
        ),
        Err(Md5BatchError::Backend)
    );
    assert_eq!(output, [[0xa5; 16]; 8]);
}
