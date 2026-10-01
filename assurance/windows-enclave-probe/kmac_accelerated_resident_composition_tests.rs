use super::*;
use brynja_mac_kmac::{Fips202BitString, Fips202Output, Kmac128, Kmac256, KmacXof128, KmacXof256};

fn reference(
    id: u64,
    key: &[u8],
    kl: u8,
    custom: &[u8],
    cl: u8,
    width: usize,
    last: u8,
) -> Vec<u8> {
    let key = Fips202BitString::new(key, kl).unwrap();
    let custom = Fips202BitString::new(custom, cl).unwrap();
    let empty = Fips202BitString::new(&[], 0).unwrap();
    let mut bytes = std::vec![0; width];
    let out = Fips202Output::new(&mut bytes, last).unwrap();
    let output = match id {
        1 => Kmac128::new_bits(key, custom)
            .unwrap()
            .finalize_secret_bits(empty, out)
            .unwrap(),
        2 => Kmac256::new_bits(key, custom)
            .unwrap()
            .finalize_secret_bits(empty, out)
            .unwrap(),
        3 => KmacXof128::new_bits(key, custom)
            .unwrap()
            .finalize_bits_xof(empty)
            .unwrap()
            .squeeze_final_bits_secret(out)
            .unwrap(),
        _ => KmacXof256::new_bits(key, custom)
            .unwrap()
            .finalize_bits_xof(empty)
            .unwrap()
            .squeeze_final_bits_secret(out)
            .unwrap(),
    };
    output.expose().to_vec()
}

#[test]
fn retained_rekey_all_sixteen_pairs_matches_portable() {
    for source in 1..=4 {
        for target in 1..=4 {
            let mut page = Box::new(Page::empty());
            let mut r = Resident::new(&mut page).unwrap();
            let mut seq = 0;
            setup(&mut r, &mut seq, source, &[0xa5; 32], 8, &[], 0);
            finish(&mut r, &mut seq, source, &[], 0, 33, 3);
            if source > 2 {
                seq += 1;
                let mut h = header(seq, 0, 0, 3, 33);
                field(&mut h, 7, 1);
                r.execute(SQUEEZE, &h, &[], |_| panic!("retained copy"))
                    .unwrap();
            }
            // Reference key exists only in this test; the worker never exports it.
            let key = reference(source, &[0xa5; 32], 8, &[], 0, 33, 3);
            seq += 1;
            let mut h = header(seq, target, 0, 0, 0);
            field(&mut h, 10, 11);
            r.execute(REKEY, &h, &[], |_| panic!("rekey copy")).unwrap();
            feed(&mut r, &mut seq, CUSTOM, &[0xa5, 3], 3);
            send(&mut r, &mut seq, CUSTOM_END, 0, &[], 0, 0);
            finish(&mut r, &mut seq, target, &[], 0, 32, 8);
            assert_eq!(
                output(&mut r, &mut seq, target, 32, 8),
                reference(target, &key, 3, &[0xa5, 3], 3, 32, 8)
            );
            drop(r);
            cleared(&page);
        }
    }
}

#[test]
fn incremental_xof_preserves_position_across_rate_boundary() {
    for id in [3, 4] {
        let mut page = Box::new(Page::empty());
        let mut r = Resident::new(&mut page).unwrap();
        let mut seq = 0;
        setup(&mut r, &mut seq, id, &[0x42; 32], 8, &[], 0);
        finish(&mut r, &mut seq, id, &[], 0, 0, 0);
        send(&mut r, &mut seq, SQUEEZE, 0, &[], 8, 169);
        seq += 1;
        let mut actual = Vec::new();
        r.execute(EXPORT, &header(seq, id, 0, 8, 169), &[], |bytes| {
            actual.extend_from_slice(bytes);
            true
        })
        .unwrap();
        actual.extend_from_slice(&output(&mut r, &mut seq, id, 17, 3));
        assert_eq!(actual, reference(id, &[0x42; 32], 8, &[], 0, 186, 3));
        drop(r);
        cleared(&page);
    }
}
