//! Hosted ordinary MD5 selection and batch output acceptance.
#![cfg(feature = "runtime-execution")]
use brynja_legacy_md5_std::execution::{self, Mode, PublicData};

#[test]
fn hosted_selection_batches_and_revocation() -> Result<(), Box<dyn std::error::Error>> {
    let selected = execution::select(Mode::Prefer)?;
    assert_eq!(selected.backend(), execution::availability().ok());
    assert_eq!(execution::select(Mode::Portable)?.backend(), None);
    if execution::availability().is_err() {
        assert!(execution::select(Mode::Require).is_err());
    }
    let data = [0u8; 128];
    let inputs =
        [Some(brynja_legacy_md5::BitString::new(&data, 8).map_err(|_| "invalid test bits")?); 8];
    let mut output = [[0xa5; 16]; 8];
    let report = selected.digest(
        &inputs,
        &mut output,
        &mut brynja_legacy_md5::Md5BatchControl::new(24),
        PublicData::acknowledge(),
    )?;
    assert_eq!(output, [brynja_legacy_md5::md5(&data)?; 8]);
    assert_eq!(report.backend, selected.backend());
    assert_eq!(
        report.work.vector_blocks,
        if selected.backend().is_some() { 16 } else { 0 }
    );
    println!("MD5_HOSTED_OPERATIONAL: {:?}", report.backend);
    selected.quarantine();
    let before = output;
    assert!(
        selected
            .digest(
                &inputs,
                &mut output,
                &mut brynja_legacy_md5::Md5BatchControl::new(24),
                PublicData::acknowledge()
            )
            .is_err()
    );
    assert_eq!(output, before);
    Ok(())
}
