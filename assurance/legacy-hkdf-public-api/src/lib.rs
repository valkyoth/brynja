//! Explicit legacy-only downstream consumer; no modern or implicit hash route.
#![no_std]
#![forbid(unsafe_code)]

#[path = "../../hkdf-public-api-common.rs"]
mod common;
use brynja_legacy_hkdf::{Error, LegacyUse, Sha1Prk};
pub use common::Failure;
use common::{matches_hex, require};

/// RFC 5869 A.4–A.7 through the separately selected compatibility crate.
pub fn rfc_vectors() -> Result<(), Failure> {
    for case in &common::SHA1 {
        let mut storage = [0xa5; 20];
        let mut imported = [0xa5; 20];
        let mut output = [0xa5; 82];
        let mut repeated = [0xa5; 82];
        let n = case.okm.len() / 2;
        let prk = Sha1Prk::extract(LegacyUse::acknowledge(), case.salt, case.ikm, &mut storage)
            .map_err(|_| Failure::Api)?;
        require(matches_hex(prk.expose(), case.prk))?;
        let copy = Sha1Prk::import(LegacyUse::acknowledge(), prk.expose(), &mut imported)
            .map_err(|_| Failure::Api)?;
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
        require(storage == [0; 20] && imported == [0; 20])?;
    }
    Ok(())
}

/// Exact block boundaries, public-error rollback and successful clearing.
pub fn bounds() -> Result<(), Failure> {
    let mut storage = [0; 20];
    let prk = Sha1Prk::extract(
        LegacyUse::acknowledge(),
        Some(b"salt"),
        b"ikm",
        &mut storage,
    )
    .map_err(|_| Failure::Api)?;
    let mut output = [0xa5; 5120];
    for n in [0, 1, 19, 20, 21, 5099, 5100] {
        output.fill(0xa5);
        let key = prk
            .expand_parts(&[b"con", &[], b"text"], &mut output[..n])
            .map_err(|_| Failure::Api)?;
        require(key.expose().len() == n)?;
        if n == 5100 {
            require(matches_hex(
                &key.expose()[5080..],
                "1b5f090b4a9503493ad9861ab6b0dfeea020bf9d",
            ))?;
        }
        require(key.clear().is_some() == (n != 0))?;
        require(output[..n].iter().all(|b| *b == 0) && output[n..].iter().all(|b| *b == 0xa5))?;
    }
    for n in [5101, 5120] {
        output.fill(0xa5);
        require(
            prk.expand_parts(&[b"con", b"text"], &mut output[..n]).err()
                == Some(Error::OutputLength),
        )?;
        require(output.iter().all(|b| *b == 0xa5))?;
    }
    drop(
        prk.expand(b"still usable", &mut output[..20])
            .map_err(|_| Failure::Api)?,
    );
    let _ = prk.clear();
    require(storage == [0; 20])
}

/// Multipart ordering, partition equivalence and output cleanup.
pub fn multipart_info() -> Result<(), Failure> {
    let mut storage = [0; 20];
    let prk = Sha1Prk::extract(LegacyUse::acknowledge(), None, b"ikm", &mut storage)
        .map_err(|_| Failure::Api)?;
    common::multipart_cases(20, |whole, parts, n| {
        let mut a = [0xa5; 23];
        let mut b = [0xa5; 23];
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

/// Unaligned subslices, salt choices, exact owner extents and failed admission.
pub fn ownership_and_errors() -> Result<(), Failure> {
    let mut shared = [0x42; 81];
    let (prefix, rest) = shared.split_at_mut(3);
    let (ikm, rest) = rest.split_at_mut(17);
    let (storage, output) = rest.split_at_mut(20);
    {
        let prk = Sha1Prk::extract(LegacyUse::acknowledge(), None, ikm, storage)
            .map_err(|_| Failure::Api)?;
        let _key = prk
            .expand_parts(&[&prefix[1..2], &[], &prefix[2..]], output)
            .map_err(|_| Failure::Api)?;
    }
    require(prefix == [0x42; 3] && ikm == [0x42; 17])?;
    require(storage.iter().chain(output.iter()).all(|b| *b == 0))?;
    for salt in [None, Some(&[][..]), Some(&[0; 20][..])] {
        let mut storage = [0; 20];
        let prk = Sha1Prk::extract(LegacyUse::acknowledge(), salt, &[], &mut storage)
            .map_err(|_| Failure::Api)?;
        require(matches_hex(
            prk.expose(),
            "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
        ))?;
    }
    let mut wrong = [0xa5; 19];
    require(
        Sha1Prk::extract(LegacyUse::acknowledge(), None, b"ikm", &mut wrong).err()
            == Some(Error::DestinationLength),
    )?;
    require(
        Sha1Prk::import(LegacyUse::acknowledge(), &[1; 19], &mut wrong).err()
            == Some(Error::PrkLength),
    )?;
    require(
        Sha1Prk::import(LegacyUse::acknowledge(), &[1; 20], &mut wrong).err()
            == Some(Error::DestinationLength),
    )?;
    require(wrong == [0xa5; 19])?;
    let mut long = [0xa5; 82];
    let owner = Sha1Prk::import(LegacyUse::acknowledge(), &[0x55; 80], &mut long[1..81])
        .map_err(|_| Failure::Api)?;
    let _ = owner.clear();
    require(long[0] == 0xa5 && long[81] == 0xa5 && long[1..81].iter().all(|b| *b == 0))
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
    fn limits() -> Result<(), Failure> {
        bounds()
    }
    #[test]
    fn multipart() -> Result<(), Failure> {
        multipart_info()
    }
    #[test]
    fn ownership() -> Result<(), Failure> {
        ownership_and_errors()?;
        let mut storage = [0xa5; 20];
        let mut output = [0xa5; 43];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let prk = Sha1Prk::extract(
                LegacyUse::acknowledge(),
                None,
                b"synthetic ikm",
                &mut storage,
            )
            .unwrap();
            let key = {
                let info = *b"info";
                let parts = [&info[..2], &[], &info[2..]];
                prk.expand_parts(&parts, &mut output[1..42]).unwrap()
            };
            assert_eq!(key.expose().len(), 41);
            panic!("synthetic consumer unwind");
        }));
        require(result.is_err())?;
        require(storage == [0; 20])?;
        require(output[0] == 0xa5 && output[42] == 0xa5)?;
        require(output[1..42].iter().all(|b| *b == 0))
    }
}
