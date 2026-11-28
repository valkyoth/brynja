//! Public known answers, partition invariance and key lifecycle regressions.
use brynja_mac_poly1305::{Error, OneTimeKey};

fn decode(s: &str) -> Vec<u8> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty());
    pairs
        .iter()
        .map(|pair| {
            match core::str::from_utf8(pair)
                .ok()
                .and_then(|v| u8::from_str_radix(v, 16).ok())
            {
                Some(byte) => byte,
                None => unreachable!("invalid test fixture"),
            }
        })
        .collect()
}

#[test]
fn rfc_answers_all_splits_and_tag_positions() {
    let mut cases = 0u32;
    for row in include_str!("data/rfc8439.tsv").lines() {
        let fields: Vec<_> = row.split('\t').collect();
        let [id, k, m, t] = fields.as_slice() else {
            unreachable!("fixture fields")
        };
        let Ok(key) = <[u8; 32]>::try_from(decode(k)) else {
            unreachable!("fixture key")
        };
        let msg = decode(m);
        let Ok(tag) = <[u8; 16]>::try_from(decode(t)) else {
            unreachable!("fixture tag")
        };
        for split in 0..=msg.len() {
            let mut storage = key;
            let mut mac = OneTimeKey::new(&mut storage).start();
            let (prefix, suffix) = msg.split_at(split);
            assert_eq!(mac.update(prefix), Ok(()));
            assert_eq!(mac.update(&[]), Ok(()));
            assert_eq!(mac.update(suffix), Ok(()));
            assert_eq!(mac.finalize(), tag, "{id} split {split}");
            assert_eq!(storage, [0; 32]);
        }
        for changed in 0..=16 {
            let mut supplied = tag;
            let mut storage = key;
            let expected = if let Some(byte) = supplied.get_mut(changed) {
                *byte ^= 1;
                Err(Error::Authentication)
            } else {
                Ok(())
            };
            let mut mac = OneTimeKey::new(&mut storage).start();
            for byte in msg.chunks(1) {
                assert_eq!(mac.update(byte), Ok(()));
            }
            assert_eq!(mac.verify(&supplied), expected, "{id} changed {changed}");
            assert_eq!(storage, [0; 32]);
        }
        cases = cases.saturating_add(1);
    }
    assert_eq!(cases, 12);
}

#[test]
fn empty_message_and_abandoned_keys() {
    let mut storage = [0xa5; 32]; // public test data
    let state = OneTimeKey::new(&mut storage).start();
    assert_eq!(state.finalize(), [0xa5; 16]);
    assert_eq!(storage, [0; 32]);
    storage.fill(0x35);
    drop(OneTimeKey::new(&mut storage));
    assert_eq!(storage, [0; 32]);
    storage.fill(0x62);
    let mut state = OneTimeKey::new(&mut storage).start();
    assert_eq!(state.update(&[1; 19]), Ok(()));
    drop(state);
    assert_eq!(storage, [0; 32]);
}
