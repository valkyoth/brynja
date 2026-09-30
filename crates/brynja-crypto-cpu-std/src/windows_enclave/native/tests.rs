#[test]
fn native_layout_and_capability_query_do_not_open_an_image() {
    let _ = super::sys::supported();
}

use super::super::{
    Digest, Error, ImagePolicy, PublicDeclassification, Session, State, engine::Engine,
};
use std::path::Path;
static POLICY: ImagePolicy = ImagePolicy::reviewed_sha256(
    [
        169, 57, 53, 139, 154, 188, 165, 41, 194, 197, 155, 2, 200, 34, 107, 218, 246, 100, 134,
        41, 51, 26, 41, 147, 125, 83, 215, 113, 175, 213, 185, 69,
    ],
    [66, 82, 89, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [80, 82, 79, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    1,
    1,
    [0, 0],
);

fn development(location: &Path) -> Result<Session, Error> {
    // Test-only access to the private constructor. Compiled out of the library;
    // there is no Cargo feature or runtime flag that enables this bypass.
    let backend = super::Backend::open_with(location, &POLICY, |pin| {
        assert_eq!(pin.signature(), Err(Error::Signature));
        Ok(())
    })?;
    Ok(Session {
        inner: Engine::new(backend),
    })
}
fn release(digest: Digest<'_>) -> Result<[u8; 32], Error> {
    let mut output = [0xa5; 32];
    digest.declassify(&mut output, PublicDeclassification::acknowledge())?;
    Ok(output)
}

#[test]
#[ignore = "Requires explicit reviewed development image, VBS/HVCI and test-signing host; never a production qualification"]
fn native_development_owner_campaign() -> Result<(), Box<dyn std::error::Error>> {
    let location = std::env::var_os("BRYNJA_ENCLAVE_TEST_IMAGE")
        .ok_or("BRYNJA_ENCLAVE_TEST_IMAGE required")?;
    let location = Path::new(&location);
    assert!(matches!(
        Session::open(location, &POLICY),
        Err(Error::Signature)
    ));
    let mut owner = development(location)?;
    assert_eq!(owner.state(), State::Ready);
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(location)
            .is_err()
    );
    assert!(matches!(owner.hash(&[0; 1025]), Err(Error::Bounds)));
    assert_eq!(owner.state(), State::Ready);
    for length in [
        0usize, 1, 3, 55, 56, 63, 64, 65, 127, 128, 129, 255, 512, 1023, 1024,
    ] {
        let mut message = vec![0x37; length];
        let expected = brynja_hash_sha2::sha256(&message).map_err(|_| Error::Protocol)?;
        let digest = owner.hash(&message)?;
        message.fill(0); // The original borrow has ended; result is retained.
        let public = release(digest)?;
        assert_eq!(&public, expected.as_bytes());
    }
    let digest = owner.hash(b"abc")?;
    assert_eq!(
        release(digest)?,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
    let digest = owner.hash(b"abc")?;
    let mut expected = *brynja_hash_sha2::sha256(b"abc")
        .map_err(|_| Error::Protocol)?
        .as_bytes();
    let mut digest = digest;
    for _ in 0..5 {
        digest = digest.rehash()?;
        expected = *brynja_hash_sha2::sha256(&expected)
            .map_err(|_| Error::Protocol)?
            .as_bytes();
    }
    assert_eq!(release(digest)?, expected);
    owner.hash(b"cancelled")?.cancel()?;
    assert_eq!(owner.state(), State::Ready);
    drop(owner.hash(b"abandoned")?);
    assert_eq!(owner.state(), State::Quarantined);
    assert!(matches!(
        owner.hash(b"no fallback"),
        Err(Error::Quarantined)
    ));
    owner.close()?;
    owner.close()?;
    assert_eq!(owner.state(), State::Closed);
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(location)
            .is_ok()
    );
    let mut owner = development(location)?;
    std::mem::forget(owner.hash(b"forgotten")?);
    assert_eq!(owner.state(), State::Busy);
    assert!(matches!(owner.hash(b"no reuse"), Err(Error::Busy)));
    owner.close()?;
    let mut owner = development(location)?;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let result = owner.hash(b"recoverable unwind");
            assert!(result.is_ok());
            std::panic::resume_unwind(Box::new("controlled caller unwind"));
        }))
        .is_err()
    );
    assert_eq!(owner.state(), State::Quarantined);
    owner.close()?;
    let mut owner = development(location)?;
    owner.hash(b"parent drop")?.cancel()?;
    drop(owner);
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(location)
            .is_ok()
    );
    println!(
        "WINDOWS_ENCLAVE_OWNER: PASS; vectors=16; retained_rehash=5; caller_unwind=PASS; production_signature=REJECTED; development_only=true"
    );
    Ok(())
}
