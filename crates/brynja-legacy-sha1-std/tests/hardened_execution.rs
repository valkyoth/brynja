//! Hosted hardened owner and typed-output acceptance.
#![cfg(feature = "runtime-hardened-execution")]
use brynja_legacy_sha1::{PublicDeclassification, sha1};
use brynja_legacy_sha1_std::hardened_execution::{Mode, availability, select};

#[test]
fn hosted_hardened_selection_and_revocation() -> Result<(), Box<dyn std::error::Error>> {
    let preferred = select(Mode::Prefer)?;
    assert_eq!(preferred.report().backend.is_some(), availability().is_ok());
    assert_eq!(select(Mode::Require).is_ok(), availability().is_ok());
    println!(
        "\nSHA1_HOSTED_HARDENED: {}",
        preferred
            .report()
            .backend
            .map_or("portable", |backend| backend.as_str())
    );
    let portable = select(Mode::Portable)?;
    assert_eq!(portable.report().backend, None);
    for owner in [portable, preferred] {
        let mut output = [0xa5; 20];
        owner.hash_public(b"abc", &mut output, PublicDeclassification::acknowledge())?;
        assert_eq!(output, sha1(b"abc")?);
        {
            let secret = owner.hash_secret(b"abc", &mut output)?;
            assert_eq!(secret.expose(), sha1(b"abc")?);
        }
        assert_eq!(output, [0; 20]);
        let state = owner.start()?;
        owner.quarantine();
        output.fill(0xa5);
        assert!(state.finalize_secret(&mut output).is_err());
        assert_eq!(output, [0; 20]);
    }
    Ok(())
}
