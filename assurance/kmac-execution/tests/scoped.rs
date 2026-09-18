#![cfg(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha3"
    )
))]
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use brynja_mac_kmac::{
    Fips202BitString, KmacError,
    execution::{KeccakSession, in_place as api},
};
use std::io;
#[path = "scoped/xof.rs"]
mod xof;
fn bad(e: impl core::fmt::Debug) -> io::Error {
    io::Error::other(format!("scoped lifecycle: {e:?}"))
}
fn owner() -> Result<Authority, io::Error> {
    Authority::new(if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    })
    .map_err(bad)
}
fn session(owner: &Authority) -> Result<KeccakSession<'_>, io::Error> {
    KeccakSession::from_static(owner).map_err(bad)
}

macro_rules! lifecycle {
    ($workspace:ident, $reference:ident, $owner:ident) => {{
        let mut workspace = api::$workspace::new(session(&$owner)?).map_err(bad)?;
        let key = [0x42; 32];
        let mut expected = [0; 257];
        let _tag = brynja_mac_kmac::$reference(&key, b"secret message", b"domain", &mut expected)
            .map_err(bad)?;
        let mut out = [0xa5; 257];
        let mut scratch = [0x5a; 300];
        let secret = workspace
            .with(&key, b"domain", |mut state| {
                state.update(b"secret message")?;
                state.finalize_secret(&mut out)
            })
            .map_err(bad)?
            .map_err(bad)?;
        assert_eq!(secret.expose(), expected);
        drop(secret);
        assert_eq!(out, [0; 257]);
        workspace
            .with_scratch(&key, b"domain", &mut scratch, |mut state| {
                state.update(b"secret message")?;
                state.finalize_tag(&mut out).map(|_| ())
            })
            .map_err(bad)?
            .map_err(bad)?;
        assert_eq!(out, expected);
        assert_eq!(scratch, [0; 300]);
        for width in [0, 1, 168, 256] {
            let mut scratch = vec![0x5a; width];
            out.fill(0xa5);
            assert!(
                workspace
                    .with_scratch(&key, b"domain", &mut scratch, |state| state
                        .finalize_tag(&mut out))
                    .map_err(bad)?
                    .is_err()
            );
            assert_eq!(out, [0xa5; 257]);
            assert!(scratch.iter().all(|b| *b == 0));
        }
        assert!(
            workspace
                .with(&key, b"", |state| state.finalize_tag(&mut out))
                .map_err(bad)?
                .is_err()
        );
        assert_eq!(out, [0xa5; 257]);
        scratch.fill(0xa5);
        assert!(matches!(
            workspace.with_scratch(&[], b"", &mut scratch, |_| panic!(
                "weak key entered callback"
            )),
            Err(KmacError::KeyTooShort)
        ));
        assert_eq!(scratch, [0; 300]);
        for valid in [0, 9, 255] {
            out.fill(0xa5);
            assert!(
                workspace
                    .with(&key, b"", |state| state.finalize_secret_bits(
                        Fips202BitString::new(&[], 0).map_err(|_| KmacError::InvalidBitString)?,
                        &mut out,
                        valid
                    ))
                    .map_err(bad)?
                    .is_err()
            );
            assert_eq!(out, [0; 257]);
        }
        for mode in 0..3 {
            workspace
                .with(&key, b"domain", |mut state| {
                    state.update(b"secret message")?;
                    match mode {
                        0 => state.cancel(),
                        1 => drop(state),
                        _ => core::mem::forget(state),
                    };
                    Ok::<(), KmacError>(())
                })
                .map_err(bad)?
                .map_err(bad)?;
            let secret = workspace
                .with(&key, b"domain", |mut state| {
                    state.update(b"secret message")?;
                    state.finalize_secret(&mut out)
                })
                .map_err(bad)?
                .map_err(bad)?;
            assert_eq!(secret.expose(), expected);
            drop(secret);
        }
        scratch.fill(0xa5);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = workspace.with_scratch(&key, b"domain", &mut scratch, |state| {
                core::mem::forget(state);
                std::panic::resume_unwind(Box::new(()));
            });
        }));
        assert!(caught.is_err());
        assert_eq!(scratch, [0; 300]);
        let yes = workspace
            .with(&key, b"domain", |mut state| {
                state.update(b"secret message")?;
                state.verify(&expected)
            })
            .map_err(bad)?
            .map_err(bad)?;
        assert!(yes.expose_public());
        expected[0] ^= 1;
        let no = workspace
            .with(&key, b"domain", |mut state| {
                state.update(b"secret message")?;
                state.verify(&expected)
            })
            .map_err(bad)?
            .map_err(bad)?;
        assert!(!no.expose_public());
    }};
}
#[test]
fn scoped_native_fixed_output_lifecycle() -> Result<(), io::Error> {
    let authority = owner()?;
    lifecycle!(Kmac128Workspace, kmac128, authority);
    lifecycle!(Kmac256Workspace, kmac256, authority);
    Ok(())
}
#[test]
fn scoped_revocation_cannot_reopen_or_fallback() -> Result<(), io::Error> {
    let authority = owner()?;
    let mut secret = api::Kmac256Workspace::new(session(&authority)?).map_err(bad)?;
    let mut public = api::Kmac128Workspace::new(session(&authority)?).map_err(bad)?;
    let mut bytes = [0xa5; 32];
    secret
        .with(&[0; 32], b"", |mut state| {
            state.update(b"secret")?;
            authority.quarantine();
            assert!(state.update(&[]).is_err());
            assert!(state.finalize_secret(&mut bytes).is_err());
            Ok::<(), KmacError>(())
        })
        .map_err(bad)?
        .map_err(bad)?;
    assert_eq!(bytes, [0; 32]);
    let mut called = false;
    assert!(secret.with(&[0; 32], b"", |_| called = true).is_err());
    assert!(!called);
    let mut scratch = [0xa5; 40];
    bytes.fill(0xa5);
    assert!(
        public
            .with_scratch(&[0; 32], b"", &mut scratch, |_| called = true)
            .is_err()
    );
    assert_eq!(scratch, [0; 40]);
    assert!(!called);
    assert_eq!(bytes, [0xa5; 32]);
    assert!(session(&authority).is_err());
    Ok(())
}
