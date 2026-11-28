use brynja_aead_chacha20poly1305::{Error, Opener, Sealer};

// Each layout replays the same published test vector, not a new live message.
pub(crate) fn public_api(
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
