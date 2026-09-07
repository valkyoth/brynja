//! Final ordinary-build consumer: no evidence cfg and no execution authority.
#![no_std]

mod batch;
#[path = "../../legacy-hash-public-api/src/vectors.rs"]
mod frozen;

/// Replay the unchanged portable contract, then bounded batch/route acceptance.
pub fn acceptance() -> Result<usize, &'static str> {
    brynja_legacy_hash_public_api_fixture::acceptance();
    reject_unadmitted()?;
    batch::failures()?;
    let mut comparisons = 0;
    for (data, _, expected) in frozen::FILES {
        comparisons += batch::check(data, if data.is_empty() { 0 } else { 8 }, expected)?;
    }
    for (data, width, _, expected) in frozen::BITS {
        comparisons += batch::check(data, *width, expected)?;
    }
    if comparisons != 160 {
        return Err("frozen batch case count changed");
    }
    Ok(comparisons)
}

fn reject_unadmitted() -> Result<(), &'static str> {
    use brynja_legacy_md5::{Md5Backend, Md5BackendError, Md5BackendSession};
    use brynja_legacy_sha1::{Sha1Backend, Sha1BackendError, Sha1BackendSession};
    if Sha1Backend::X86Sha.is_admitted()
        || Sha1Backend::Aarch64Sha1.is_admitted()
        || Md5Backend::X86Avx2.is_admitted()
        || Md5Backend::Aarch64Neon.is_admitted()
    {
        return Err("backend admission requires a new reviewed acceptance contract");
    }
    if !matches!(
        Sha1BackendSession::for_compiled_target().err(),
        Some(Sha1BackendError::MissingFeatures | Sha1BackendError::NotAdmitted)
    ) || !matches!(
        Md5BackendSession::for_compiled_target().err(),
        Some(Md5BackendError::MissingFeatures | Md5BackendError::NotAdmitted)
    ) {
        return Err("ordinary build acquired an unadmitted instruction route");
    }
    Ok(())
}

/// Bounded interpreter coverage for the newly composed downstream lifecycle.
pub fn dynamic_lifecycle() -> Result<(), &'static str> {
    reject_unadmitted()?;
    batch::failures()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    #[test]
    fn frozen_portable_and_bounded_batch_profiles() {
        assert_eq!(super::acceptance(), Ok(160));
    }

    #[test]
    fn dynamic_final_lifecycle() {
        assert_eq!(super::dynamic_lifecycle(), Ok(()));
    }

    #[test]
    fn dynamic_full_width_comparison_rejects_every_mismatch() {
        let expected = [0xa5; 128];
        assert_eq!(super::batch::output_matches(&expected, &expected), Ok(true));
        for index in 0..128 {
            let mut actual = expected;
            actual[index] ^= 1;
            assert_eq!(super::batch::output_matches(&actual, &expected), Ok(false));
        }
        for length in [0, 16, 127, 129] {
            let data = [0xa5; 129];
            assert!(super::batch::output_matches(&data[..length], &expected).is_err());
            assert!(super::batch::output_matches(&expected, &data[..length]).is_err());
        }
    }

    #[test]
    fn dynamic_neighbor_drop_unwind_clears_live_secret_output() {
        use brynja_legacy_md5::{BitString, HardenedMd5Batch, Md5BatchControl};
        struct PanickingNeighbor;
        impl Drop for PanickingNeighbor {
            fn drop(&mut self) {
                panic!("neighbor destructor initiates recoverable unwind");
            }
        }
        let mut output = [[0xa5; 16]; 8];
        let input = BitString::new(b"a", 8).ok();
        assert!(input.is_some());
        let mut held_nonzero_result = false;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let result = HardenedMd5Batch::new().digest_secret(
                &[input; 8],
                &mut output,
                &mut Md5BatchControl::new(32),
            );
            held_nonzero_result = result
                .as_ref()
                .is_ok_and(|(secret, _)| secret.expose().iter().any(|byte| *byte != 0));
            // Dropped before `result`, so the secret owner is destroyed while
            // unwinding. catch_unwind only lets this test inspect the outcome.
            let _neighbor = PanickingNeighbor;
        }));
        assert!(caught.is_err());
        assert!(held_nonzero_result);
        assert_eq!(output, [[0; 16]; 8]);
    }

    #[test]
    fn dynamic_batch_unwind_clears_complete_secret_output() {
        use brynja_legacy_md5::{BitString, HardenedMd5Batch, Md5BatchControl};
        let input = BitString::new(b"a", 8).ok();
        assert!(input.is_some());
        let mut output = [[0xa5; 16]; 8];
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut cancel = || -> bool { panic!("recoverable consumer cancellation unwind") };
            let _result = HardenedMd5Batch::new().digest_secret(
                &[input; 8],
                &mut output,
                &mut Md5BatchControl::with_cancellation(32, &mut cancel),
            );
        }));
        assert!(caught.is_err());
        assert_eq!(output, [[0; 16]; 8]);
    }
}
