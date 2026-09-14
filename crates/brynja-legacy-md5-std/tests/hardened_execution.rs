//! Hosted hardened MD5 selection and typed output lifetime checks.
#![cfg(feature = "runtime-hardened-execution")]
use brynja_legacy_md5::{BitString, Md5BatchControl, PublicDeclassification};
use brynja_legacy_md5_std::hardened_execution::{self, Mode};

#[test]
fn hosted_hardened_selection_and_owned_output() -> Result<(), Box<dyn std::error::Error>> {
    let portable = hardened_execution::select(Mode::Portable)?;
    assert!(portable.backend().is_none());
    let preferred = hardened_execution::select(Mode::Prefer)?;
    assert_eq!(preferred.backend(), hardened_execution::availability().ok());
    let data = [0xa5; 128];
    let inputs = [Some(BitString::new(&data, 8).map_err(|_| "bits")?); 8];
    let mut public = [[0; 16]; 8];
    for cancelled in [false, true] {
        let mut callback = || cancelled;
        let mut rejected = [[0xa5; 16]; 8];
        assert!(
            preferred
                .batch()
                .digest_secret(
                    &inputs,
                    &mut rejected,
                    &mut Md5BatchControl::with_cancellation(0, &mut callback),
                )
                .is_err()
        );
        assert_eq!(rejected, [[0; 16]; 8]);
        assert_eq!(
            preferred.health(),
            brynja_legacy_md5::Md5BackendHealth::Healthy
        );
    }
    let report = preferred.batch().digest_public(
        &inputs,
        &mut public,
        &mut Md5BatchControl::new(24),
        PublicDeclassification::acknowledge(),
    )?;
    assert_eq!(public, [brynja_legacy_md5::md5(&data)?; 8]);
    assert_eq!(
        report.work.vector_blocks,
        if preferred.backend().is_some() { 16 } else { 0 }
    );
    let mut secret = [[0xa5; 16]; 8];
    let (owner, secret_report) =
        preferred
            .batch()
            .digest_secret(&inputs, &mut secret, &mut Md5BatchControl::new(24))?;
    assert_eq!(owner.expose(), public.as_flattened());
    assert_eq!(secret_report, report);
    drop(owner);
    assert_eq!(secret, [[0; 16]; 8]);
    preferred.quarantine();
    assert!(
        preferred
            .batch()
            .digest_secret(&inputs, &mut secret, &mut Md5BatchControl::new(24))
            .is_err()
    );
    println!("MD5_HOSTED_HARDENED: {:?}", report.backend);
    Ok(())
}
