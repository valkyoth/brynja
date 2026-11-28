//! Public known-answer and independent-oracle records; no application keys.
use brynja_aead_chacha20poly1305::{Error, Opener, Sealer, execution::Pair};

pub(crate) fn paired_api(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    plain: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
) -> Option<()> {
    let mut pair = Pair::probe().ok()?;
    let (prefix, suffix) = nonce.split_at(4);
    for in_place in [false, true] {
        let mut sender = Sealer::from_reserved_range(
            key,
            prefix.try_into().ok()?,
            u64::from_be_bytes(suffix.try_into().ok()?),
            1,
        )
        .ok()?;
        let mut seal = sender.with_pair(&mut pair).ok()?;
        let mut dst = plain.to_vec();
        let mut work = vec![0x56; ct.len()];
        let sent = if in_place {
            seal.seal_in_place(aad, &mut dst, &mut work)
        } else {
            dst.fill(0x43);
            seal.seal(aad, plain, &mut dst, &mut work)
        }
        .ok()?;
        (sent == (nonce, *tag) && dst == ct && work.iter().all(|b| *b == 0)).then_some(())?;
        let mut open = Opener::new(key).with_pair(&mut pair).ok()?;
        let mut reject = |n, a: &[u8], c: &[u8], t: &[u8; 16]| {
            dst.copy_from_slice(c);
            work.fill(0xb7);
            if !in_place {
                dst.fill(0xaa);
            }
            let before = dst.clone();
            let result = if in_place {
                open.open_in_place(n, a, t, &mut dst, &mut work)
            } else {
                open.open(n, a, t, c, &mut dst, &mut work)
            };
            (result == Err(Error::Authentication) && before == dst && work.iter().all(|b| *b == 0))
                .then_some(())
        };
        for index in 0..16 {
            let mut bad = *tag;
            bad[index] ^= 1;
            reject(nonce, aad, ct, &bad)?;
        }
        let mut other = nonce;
        other[0] ^= 1;
        reject(other, aad, ct, tag)?;
        let mut a = aad.to_vec();
        if let Some(last) = a.last_mut() {
            *last ^= 1;
        } else {
            a.push(0);
        }
        reject(nonce, &a, ct, tag)?;
        let mut c = ct.to_vec();
        if let Some(last) = c.last_mut() {
            *last ^= 1;
            reject(nonce, aad, &c, tag)?;
        }
        dst.copy_from_slice(ct);
        work.fill(0x55);
        if in_place {
            open.open_in_place(nonce, aad, tag, &mut dst, &mut work)
        } else {
            open.open(nonce, aad, tag, ct, &mut dst, &mut work)
        }
        .ok()?;
        (dst == plain && work.iter().all(|b| *b == 0)).then_some(())?;
    }
    Some(())
}
