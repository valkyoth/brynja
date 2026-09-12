//! Hosted authority remains distinct from observational legacy APIs.
#![cfg(feature = "runtime-execution")]
use brynja_legacy_sha1_std::execution::{self, Mode, PublicData};

#[test]
fn required_preferred_and_portable_selection_are_explicit() -> Result<(), execution::Error> {
    assert!(
        execution::select(Mode::Portable)?
            .report()
            .backend
            .is_none()
    );
    let prefer = execution::select(Mode::Prefer)?;
    println!("SHA1_HOSTED_OPERATIONAL: {:?}", prefer.report().backend);
    match execution::availability() {
        Ok(()) => {
            assert!(prefer.report().backend.is_some());
            let required = execution::select(Mode::Require)?;
            assert_eq!(required.report(), prefer.report());
        }
        Err(reason) => {
            assert!(prefer.report().backend.is_none());
            assert!(
                matches!(execution::select(Mode::Require), Err(execution::Error::Unavailable(r)) if r == reason)
            );
        }
    }
    assert_eq!(
        prefer.hash(b"abc", PublicData::acknowledge()).ok(),
        brynja_legacy_sha1::sha1(b"abc").ok()
    );
    prefer.quarantine();
    assert!(prefer.hash(b"abc", PublicData::acknowledge()).is_err());
    Ok(())
}
