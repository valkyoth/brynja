//! Byte-oriented production APIs checked against the same independent oracle.
use brynja_mac_kmac::{Kmac128, Kmac256, KmacError};
use std::io;

fn failure() -> io::Error {
    io::Error::other("production byte/policy mismatch")
}

pub(crate) fn admission() -> Result<(), io::Error> {
    macro_rules! check {
        ($state:ident, $size:expr) => {{
            if !matches!($state::new(&[], &[]), Err(KmacError::KeyTooShort)) {
                return Err(failure());
            }
            let key = [7; $size];
            let mut output = [0xa5; 1];
            if !matches!(
                $state::new(&key, &[])
                    .map_err(|_| failure())?
                    .finalize_tag(&mut output),
                Err(KmacError::TagTooShort)
            ) || output != [0xa5; 1]
            {
                return Err(failure());
            }
            if !matches!(
                $state::new(&key, &[]).map_err(|_| failure())?.verify(&[0]),
                Err(KmacError::TagTooShort)
            ) {
                return Err(failure());
            }
        }};
    }
    check!(Kmac128, 16);
    check!(Kmac256, 32);
    Ok(())
}

pub(crate) fn check(
    algorithm: &str,
    key: &[u8],
    custom: &[u8],
    message: &[u8],
    expected: &[u8],
) -> Result<(), io::Error> {
    macro_rules! fixed {
        ($state:ident, $workspace:ident) => {{
            let mut actual: Vec<u8> = expected.iter().map(|b| !b).collect();
            let mut state = $state::new(key, custom).map_err(|_| failure())?;
            state.update(message).map_err(|_| failure())?;
            let tag = state.finalize_tag(&mut actual).map_err(|_| failure())?;
            if tag.as_bytes() != expected {
                return Err(failure());
            }
            let mut verifier = $state::new(key, custom).map_err(|_| failure())?;
            verifier.update(message).map_err(|_| failure())?;
            if !verifier
                .verify(expected)
                .map_err(|_| failure())?
                .expose_public()
            {
                return Err(failure());
            }
            for position in [0, expected.len().checked_sub(1).ok_or_else(failure)?] {
                let mut bad = expected.to_vec();
                *bad.get_mut(position).ok_or_else(failure)? ^= 1;
                let mut verifier = $state::new(key, custom).map_err(|_| failure())?;
                verifier.update(message).map_err(|_| failure())?;
                if verifier
                    .verify(&bad)
                    .map_err(|_| failure())?
                    .expose_public()
                {
                    return Err(failure());
                }
            }
            let mut workspace = brynja_mac_kmac::hardened_in_place::$workspace::new();
            actual.fill(0xa5);
            let tag = workspace
                .with(key, custom, |mut state| {
                    state.update(message)?;
                    state.finalize_tag(&mut actual)
                })
                .and_then(core::convert::identity)
                .map_err(|_| failure())?;
            if tag.as_bytes() != expected {
                return Err(failure());
            }
            let verified = workspace
                .with(key, custom, |mut state| {
                    state.update(message)?;
                    state.verify(expected)
                })
                .and_then(core::convert::identity)
                .map_err(|_| failure())?;
            if !verified.expose_public() {
                return Err(failure());
            }
            for position in [0, expected.len().checked_sub(1).ok_or_else(failure)?] {
                let mut bad = expected.to_vec();
                *bad.get_mut(position).ok_or_else(failure)? ^= 1;
                let rejected = workspace
                    .with(key, custom, |mut state| {
                        state.update(message)?;
                        state.verify(&bad)
                    })
                    .and_then(core::convert::identity)
                    .map_err(|_| failure())?;
                if rejected.expose_public() {
                    return Err(failure());
                }
            }
        }};
    }
    match algorithm {
        "kmac128" => fixed!(Kmac128, Kmac128Workspace),
        "kmac256" => fixed!(Kmac256, Kmac256Workspace),
        _ => (),
    }
    Ok(())
}
