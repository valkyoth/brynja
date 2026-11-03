//! Published protocol traces, independent of the fixture's label encoder.
use super::{Failure, Prk, Sha256, Tls13Label, matches_hex, require};

fn decode<const N: usize>(hex: &str) -> Result<[u8; N], Failure> {
    require(hex.len() == N * 2)?;
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(Failure::Contract),
        };
        *out = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(bytes)
}

fn answer(prk: &Prk<'_, Sha256>, label: &[u8], context: &[u8], hex: &str) -> Result<(), Failure> {
    let n = hex.len() / 2;
    let mut output = [0xa5; 34];
    let mut checked = [0xa5; 34];
    let spec = Tls13Label::new(label, context, n).map_err(|_| Failure::Api)?;
    {
        let key = prk
            .expand_label(label, context, &mut output[1..n + 1])
            .map_err(|_| Failure::Api)?;
        let bound = prk
            .expand_tls13(&spec, &mut checked[1..n + 1])
            .map_err(|_| Failure::Api)?;
        require(matches_hex(key.expose(), hex) && matches_hex(bound.expose(), hex))?;
    }
    for buffer in [output, checked] {
        require(buffer[0] == 0xa5 && buffer[n + 1..].iter().all(|b| *b == 0xa5))?;
        require(buffer[1..n + 1].iter().all(|b| *b == 0))?;
    }
    Ok(())
}

pub(super) fn published() -> Result<(), Failure> {
    // RFC 8448 section 3, early secret and "derived" secret (not a handshake).
    // https://www.rfc-editor.org/rfc/rfc8448#section-3
    let mut early = [0; 32];
    let prk =
        Prk::<Sha256>::extract(Some(&[0; 32]), &[0; 32], &mut early).map_err(|_| Failure::Api)?;
    require(matches_hex(
        prk.expose(),
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
    ))?;
    let empty_hash =
        decode::<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?;
    answer(
        &prk,
        b"derived",
        &empty_hash,
        "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
    )?;
    let _ = prk.clear();
    require(early == [0; 32])?;

    // RFC 9001 Appendix A.1, QUIC v1 initial secrets and client/server keys.
    // https://www.rfc-editor.org/rfc/rfc9001#appendix-A.1
    let salt = decode::<20>("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")?;
    let cid = decode::<8>("8394c8f03e515708")?;
    let mut initial = [0; 32];
    let prk = Prk::<Sha256>::extract(Some(&salt), &cid, &mut initial).map_err(|_| Failure::Api)?;
    require(matches_hex(
        prk.expose(),
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
    ))?;
    for (label, secret, key, iv, hp) in [
        (
            b"client in".as_slice(),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
            "1f369613dd76d5467730efcbe3b1a22d",
            "fa044b2f42a3fd3b46fb255c",
            "9f50449e04a0e810283a1e9933adedd2",
        ),
        (
            b"server in".as_slice(),
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
            "cf3a5331653c364c88f0f379b6067e37",
            "0ac1493ca1905853b0bba03e",
            "c206b8d9b9f0f37644430b490eeaa314",
        ),
    ] {
        answer(&prk, label, &[], secret)?;
        let mut derived_storage = [0; 32];
        let derived = prk
            .expand_label(label, &[], &mut derived_storage)
            .map_err(|_| Failure::Api)?;
        let mut imported = [0; 32];
        let traffic =
            Prk::<Sha256>::import(derived.expose(), &mut imported).map_err(|_| Failure::Api)?;
        answer(&traffic, b"quic key", &[], key)?;
        answer(&traffic, b"quic iv", &[], iv)?;
        answer(&traffic, b"quic hp", &[], hp)?;
        let _ = traffic.clear();
        let _ = derived.clear();
        require(imported == [0; 32] && derived_storage == [0; 32])?;
    }
    let _ = prk.clear();
    require(initial == [0; 32])
}
