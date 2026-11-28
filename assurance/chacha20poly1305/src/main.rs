//! Test-only: replay public RFC intermediate and final answers, not a library API.
#![forbid(unsafe_code)]

use brynja_aead_chacha20poly1305::{Error, Opener, Sealer};
use brynja_cipher_chacha::ChaCha20;
use brynja_mac_poly1305::OneTimeKey;
use std::io::{self, BufRead};

fn decode(s: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

fn replay(line: &str) -> Option<()> {
    let fields: Vec<_> = line.split('\t').map(decode).collect::<Option<_>>()?;
    let [key, nonce, aad, plain, cipher, otk, frame, tag] = fields.as_slice() else {
        return None;
    };
    let key = <&[u8; 32]>::try_from(key.as_slice()).ok()?;
    let nonce = <[u8; 12]>::try_from(nonce.as_slice()).ok()?;
    let tag = <&[u8; 16]>::try_from(tag.as_slice()).ok()?;

    let mut derived = [0; 32];
    ChaCha20::new(key, nonce, 0)
        .apply_keystream_in_place(&mut derived)
        .ok()?;
    if &derived[..] != otk {
        return None;
    }

    // Feed the same segments that a fixed-storage AEAD must authenticate.
    // The RFC gives the entire padded MAC input independently of its tag.
    let mut transcript = Vec::new();
    let mut mac = OneTimeKey::from_rfc8439_key(&mut derived).start();
    for data in [aad, cipher] {
        let pad = &[0; 16][..(16 - data.len() % 16) % 16];
        for chunk in [data.as_slice(), pad] {
            mac.update(chunk).ok()?;
            transcript.extend_from_slice(chunk);
        }
    }
    for len in [aad.len(), cipher.len()] {
        let field = u64::try_from(len).ok()?.to_le_bytes();
        mac.update(&field).ok()?;
        transcript.extend_from_slice(&field);
    }
    if &transcript != frame {
        return None;
    }
    mac.verify(tag).ok()?;
    let mut opened = cipher.clone();
    ChaCha20::new(key, nonce, 1)
        .apply_keystream_in_place(&mut opened)
        .ok()?;
    (opened == *plain && derived == [0; 32]).then_some(())?;
    public_api(key, nonce, aad, plain, cipher, tag)
}

// Each layout replays the same published test vector, not a new live message.
fn public_api(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    plain: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
) -> Option<()> {
    let (prefix, suffix) = nonce.split_at(4);
    let open = Opener::new(key);
    for in_place in [false, true] {
        let mut send = Sealer::from_reserved_range(
            key,
            prefix.try_into().ok()?,
            u64::from_be_bytes(suffix.try_into().ok()?),
            1,
        )
        .ok()?;
        let mut dst = plain.to_vec();
        let mut work = vec![0x55; plain.len()];
        let (wire_nonce, wire_tag) = if in_place {
            send.seal_in_place(aad, &mut dst, &mut work)
        } else {
            dst.fill(0x5a);
            send.seal(aad, plain, &mut dst, &mut work)
        }
        .ok()?;
        (wire_nonce == nonce && wire_tag == *tag && dst == ct && work.iter().all(|&b| b == 0))
            .then_some(())?;
        for index in 0..tag.len() {
            let mut bad = *tag;
            *bad.get_mut(index)? ^= 1;
            work.fill(0xa5);
            if !in_place {
                dst.fill(0xa5);
            }
            let before = dst.clone();
            let rejected = if in_place {
                open.open_in_place(nonce, aad, &bad, &mut dst, &mut work)
            } else {
                open.open(nonce, aad, &bad, ct, &mut dst, &mut work)
            };
            (rejected == Err(Error::Authentication)
                && dst == before
                && work.iter().all(|&b| b == 0))
            .then_some(())?;
        }
        work.fill(0x55);
        if in_place {
            open.open_in_place(nonce, aad, tag, &mut dst, &mut work)
        } else {
            open.open(nonce, aad, tag, ct, &mut dst, &mut work)
        }
        .ok()?;
        (dst == plain && work.iter().all(|&b| b == 0)).then_some(())?;
    }
    Some(())
}

fn main() -> Result<(), &'static str> {
    let mut count = 0;
    for line in io::stdin().lock().lines() {
        replay(&line.map_err(|_| "read error")?).ok_or("RFC record mismatch")?;
        count += 1;
    }
    if count == 0 {
        return Err("no RFC records");
    }
    println!("matched {count} RFC AEAD records");
    Ok(())
}
