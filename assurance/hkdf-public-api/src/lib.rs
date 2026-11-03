//! Allocation-free, downstream facade acceptance using only public APIs.
#![no_std]
#![forbid(unsafe_code)]

#[path = "../../hkdf-public-api-common.rs"]
mod common;
use brynja::crypto::hkdf::{
    Algorithm, Error, ParameterError, Prk, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
    Tls13Label,
};
pub use common::Failure;
use common::{matches_hex, require};
mod tls_vectors;

/// All RFC SHA-256 cases; compare Extract, Expand, import and cleanup.
pub fn rfc_vectors() -> Result<(), Failure> {
    for case in &common::SHA256 {
        let mut storage = [0xa5; 32];
        let mut imported = [0xa5; 32];
        let mut output = [0xa5; 82];
        let mut repeated = [0xa5; 82];
        let n = case.okm.len() / 2;
        let prk =
            Prk::<Sha256>::extract(case.salt, case.ikm, &mut storage).map_err(|_| Failure::Api)?;
        require(matches_hex(prk.expose(), case.prk))?;
        let copy = Prk::<Sha256>::import(prk.expose(), &mut imported).map_err(|_| Failure::Api)?;
        {
            let key = prk
                .expand(case.info, &mut output[..n])
                .map_err(|_| Failure::Api)?;
            let again = copy
                .expand_parts(
                    &[
                        &case.info[..case.info.len() / 2],
                        &[],
                        &case.info[case.info.len() / 2..],
                    ],
                    &mut repeated[..n],
                )
                .map_err(|_| Failure::Api)?;
            require(matches_hex(key.expose(), case.okm))?;
            require(matches_hex(again.expose(), case.okm))?;
            require(key.expose() == again.expose())?;
        }
        require(output[..n].iter().all(|b| *b == 0) && output[n..].iter().all(|b| *b == 0xa5))?;
        require(repeated[..n].iter().all(|b| *b == 0))?;
        let _ = prk.clear();
        let _ = copy.clear();
        require(storage == [0; 32] && imported == [0; 32])?;
    }
    Ok(())
}

fn bounds<A: Algorithm>(last: &str) -> Result<(), Failure> {
    let width = A::TAG_BYTES;
    let mut storage = [0xa5; 64];
    let mut output = [0xa5; 64 * 256];
    let prk = Prk::<A>::extract(Some(b"salt"), b"ikm", &mut storage[..width])
        .map_err(|_| Failure::Api)?;
    // Empty and one-byte output, one-block boundaries and the 255-block limit.
    // Just-over-limit and 256-block requests are rejected below.
    for n in [
        0,
        1,
        width - 1,
        width,
        width + 1,
        width * 255 - 1,
        width * 255,
    ] {
        output.fill(0xa5);
        let key = prk
            .expand_parts(&[b"con", &[], b"text"], &mut output[..n])
            .map_err(|_| Failure::Api)?;
        require(key.expose().len() == n)?;
        if n == width * 255 {
            require(matches_hex(&key.expose()[n - width..], last))?;
        }
        require(key.clear().is_some() == (n != 0))?;
        require(output[..n].iter().all(|b| *b == 0) && output[n..].iter().all(|b| *b == 0xa5))?;
    }
    for n in [width * 255 + 1, width * 256] {
        output.fill(0xa5);
        require(
            prk.expand_parts(&[b"con", b"text"], &mut output[..n]).err()
                == Some(Error::Parameters(ParameterError::ExpansionLength)),
        )?;
        require(output.iter().all(|b| *b == 0xa5))?;
    }
    // Rejection does not poison the PRK.
    drop(
        prk.expand(b"still usable", &mut output[..width])
            .map_err(|_| Failure::Api)?,
    );
    let _ = prk.clear();
    require(storage[..width].iter().all(|b| *b == 0))
}

/// All six explicit identities, with independent frozen T(255) answers.
pub fn all_algorithms_and_bounds() -> Result<(), Failure> {
    bounds::<Sha224>("703c6f5cd5a43f37a0aff47ed354ddfab7a531289e07b9eef4d4911b")?;
    bounds::<Sha256>("464703cef02f47b5832d1a9b7ac290bc986819abb427e68d48055d6cb7e34680")?;
    bounds::<Sha384>(
        "a7ad9ac06bad5d13eb7f7f9ccad2eda618d53d023138ca85bcbba58cbb4f5917f8dc28d1cd1c2add7ae8e75ee7f083ed",
    )?;
    bounds::<Sha512>(
        "1daead199bd11966c58506868d6719be2f9b53f1f0a92243420ba931947591218a6a860fdc4e9b4ebe770c827556c15f3601e1682b4525ced1d18e605ac1a6c5",
    )?;
    bounds::<Sha512_224>("a2683873133625d1d1d815b355885bdeee0ced96ce0b6717dc438a86")?;
    bounds::<Sha512_256>("be3f293020e88f8ccef78099765662edfe63b9ca4afd2488e994265b2c150c3a")
}

/// Every split, empty parts and ordering for all admitted identities.
pub fn multipart_info() -> Result<(), Failure> {
    multipart::<Sha224>()?;
    multipart::<Sha256>()?;
    multipart::<Sha384>()?;
    multipart::<Sha512>()?;
    multipart::<Sha512_224>()?;
    multipart::<Sha512_256>()
}

fn multipart<A: Algorithm>() -> Result<(), Failure> {
    let mut storage = [0; 64];
    let prk =
        Prk::<A>::extract(None, b"ikm", &mut storage[..A::TAG_BYTES]).map_err(|_| Failure::Api)?;
    common::multipart_cases(A::TAG_BYTES, |whole, parts, n| {
        let mut a = [0xa5; 67];
        let mut b = [0xa5; 67];
        {
            let single = prk
                .expand(whole, &mut a[1..n + 1])
                .map_err(|_| Failure::Api)?;
            let multi = prk
                .expand_parts(parts, &mut b[1..n + 1])
                .map_err(|_| Failure::Api)?;
            require(single.expose() == multi.expose())?;
        }
        for buffer in [a, b] {
            require(buffer[0] == 0xa5 && buffer[n + 1..].iter().all(|b| *b == 0xa5))?;
            require(buffer[1..n + 1].iter().all(|b| *b == 0))?;
        }
        Ok(())
    })
}

/// Explicit salt choices, borrowed subslices, canaries and import errors.
pub fn ownership_and_errors() -> Result<(), Failure> {
    let mut shared = [0x42; 149];
    let (prefix, rest) = shared.split_at_mut(3);
    let (ikm, rest) = rest.split_at_mut(17);
    let (storage, rest) = rest.split_at_mut(32);
    let (output, suffix) = rest.split_at_mut(65);
    {
        let prk = Prk::<Sha256>::extract(None, ikm, storage).map_err(|_| Failure::Api)?;
        let key = prk
            .expand_parts(&[&prefix[1..2], &[], &prefix[2..]], output)
            .map_err(|_| Failure::Api)?;
        require(key.expose().len() == 65)?;
    }
    require(prefix == [0x42; 3] && ikm == [0x42; 17] && suffix == [0x42; 32])?;
    require(storage.iter().chain(output.iter()).all(|b| *b == 0))?;
    let mut a = [0; 32];
    let mut b = [0; 32];
    let mut c = [0; 32];
    let absent = Prk::<Sha256>::extract(None, &[], &mut a).map_err(|_| Failure::Api)?;
    let empty = Prk::<Sha256>::extract(Some(&[]), &[], &mut b).map_err(|_| Failure::Api)?;
    let zero = Prk::<Sha256>::extract(Some(&[0; 32]), &[], &mut c).map_err(|_| Failure::Api)?;
    require(absent.expose() == empty.expose() && empty.expose() == zero.expose())?;
    let mut wrong = [0xa5; 31];
    require(
        Prk::<Sha256>::extract(None, b"ikm", &mut wrong).err() == Some(Error::DestinationLength),
    )?;
    require(Prk::<Sha256>::import(&[1; 31], &mut wrong).err() == Some(Error::PrkLength))?;
    require(Prk::<Sha256>::import(&[1; 32], &mut wrong).err() == Some(Error::DestinationLength))?;
    require(wrong == [0xa5; 31])?;
    let mut long = [0xa5; 82];
    let owner = Prk::<Sha256>::import(&[0x55; 80], &mut long[1..81]).map_err(|_| Failure::Api)?;
    let _ = owner.clear();
    require(long[0] == 0xa5 && long[81] == 0xa5 && long[1..81].iter().all(|b| *b == 0))
}

fn labels<A: Algorithm>() -> Result<(), Failure> {
    let mut storage = [0; 64];
    let prk = Prk::<A>::extract(
        Some(b"salt"),
        b"input key material",
        &mut storage[..A::TAG_BYTES],
    )
    .map_err(|_| Failure::Api)?;
    for (label, context, n) in [
        (b"key".as_slice(), b"abc".as_slice(), 32),
        (b"iv", &[], 12),
        (b"finished", &[0x37; 32], A::TAG_BYTES),
        (b"derived", &[0x37; 48], A::TAG_BYTES),
    ] {
        let mut output = [0xa5; 64];
        let mut checked = [0xa5; 64];
        let mut raw = [0xa5; 64];
        let mut wire = [0; 514];
        // Independent public consumer encoding, not the private library helper.
        wire[..2].copy_from_slice(&(n as u16).to_be_bytes());
        wire[2] = (6 + label.len()) as u8;
        wire[3..9].copy_from_slice(b"tls13 ");
        wire[9..9 + label.len()].copy_from_slice(label);
        wire[9 + label.len()] = context.len() as u8;
        wire[10 + label.len()..10 + label.len() + context.len()].copy_from_slice(context);
        let spec = Tls13Label::new(label, context, n).map_err(|_| Failure::Api)?;
        {
            let key = prk
                .expand_label(label, context, &mut output[..n])
                .map_err(|_| Failure::Api)?;
            let bound = prk
                .expand_tls13(&spec, &mut checked[..n])
                .map_err(|_| Failure::Api)?;
            let independent = prk
                .expand(&wire[..10 + label.len() + context.len()], &mut raw[..n])
                .map_err(|_| Failure::Api)?;
            require(key.expose() == bound.expose() && key.expose() == independent.expose())?;
            if A::TAG_BYTES == 48 && label == b"key" {
                require(matches_hex(
                    key.expose(),
                    "ef87e80909a27e763d047ffbbbf540acd17c1ed06d5a741b6a08e805fed34ebe",
                ))?;
            }
        }
        require(
            output[..n]
                .iter()
                .chain(checked[..n].iter())
                .chain(raw[..n].iter())
                .all(|b| *b == 0),
        )?;
        output.fill(0xa5);
        require(
            prk.expand_tls13(&spec, &mut output[..n - 1]).err()
                == Some(Error::Parameters(ParameterError::TlsOutputLength)),
        )?;
        require(output.iter().all(|b| *b == 0xa5))?;
    }
    let mut output = [0xa5; 32];
    for (label, context, expected) in [
        (&[][..], &[][..], ParameterError::LabelLength),
        (&[b'x'; 250][..], &[], ParameterError::LabelLength),
        (b"key", &[0; 256], ParameterError::ContextLength),
    ] {
        require(
            prk.expand_label(label, context, &mut output).err()
                == Some(Error::Parameters(expected)),
        )?;
        require(output == [0xa5; 32])?;
    }
    require(
        prk.expand_label(&[b'x'; 249], &[0; 255], &mut [])
            .map_err(|_| Failure::Api)?
            .clear()
            .is_none(),
    )
}

/// TLS cipher-suite hash examples; generic framing is not a key schedule.
pub fn tls_labels() -> Result<(), Failure> {
    labels::<Sha256>()?;
    labels::<Sha384>()?;
    tls_vectors::published()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn rfc5869() -> Result<(), Failure> {
        rfc_vectors()
    }
    #[test]
    fn identities_and_limits() -> Result<(), Failure> {
        all_algorithms_and_bounds()
    }
    #[test]
    fn multipart_info() -> Result<(), Failure> {
        super::multipart_info()
    }
    #[test]
    fn ownership() -> Result<(), Failure> {
        ownership_and_errors()?;
        let mut storage = [0xa5; 32];
        let mut output = [0xa5; 67];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let prk = Prk::<Sha256>::extract(None, b"synthetic ikm", &mut storage).unwrap();
            let key = {
                let info = *b"info";
                let parts = [&info[..2], &[], &info[2..]];
                prk.expand_parts(&parts, &mut output[1..66]).unwrap()
            }; // Neither the part list nor its bytes need to outlive the key.
            assert_eq!(key.expose().len(), 65);
            panic!("synthetic consumer unwind");
        }));
        require(result.is_err())?;
        require(storage == [0; 32])?;
        require(output[0] == 0xa5 && output[66] == 0xa5)?;
        require(output[1..66].iter().all(|b| *b == 0))
    }
    #[test]
    fn tls() -> Result<(), Failure> {
        // Equal lengths with completely different contents must have identical
        // Debug output, including alternate formatting. Neither byte array is logged.
        let a = Tls13Label::new(b"secret", b"private-context", 32).unwrap();
        let b = Tls13Label::new(b"xxxxxx", b"xxxxxxxxxxxxxxx", 32).unwrap();
        assert_eq!(std::format!("{a:?}"), std::format!("{b:?}"));
        assert_eq!(std::format!("{a:#?}"), std::format!("{b:#?}"));
        assert_eq!(
            std::format!("{a:?}"),
            "Tls13Label { label_bytes: 6, context_bytes: 15, output_bytes: 32, .. }"
        );
        tls_labels()
    }
}
