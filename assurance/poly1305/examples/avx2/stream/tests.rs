use super::*;

fn check_clear(key: &[u8; 32], ws: &Workspace) {
    assert_eq!(key, &[0; 32]);
    assert_eq!(ws.acc, [[0; 8]; 5]);
    assert_eq!(ws.tail, [0; 16]);
}

#[test]
fn every_split_scalar_vector_and_tail_boundaries() {
    for n in [
        0, 1, 15, 16, 17, 63, 64, 65, 1023, 1024, 1025, 1087, 1088, 1089, 1500, 2050,
    ] {
        let msg: Vec<_> = (0..n)
            .map(|i| (i as u8).wrapping_mul(17) ^ ((i >> 8) as u8))
            .collect();
        let key = [0xff; 32];
        let expected = crate::portable(&key, &msg);
        for split in 0..=n {
            let mut storage = key;
            let mut ws = Workspace {
                acc: [[0xff; 8]; 5],
                tail: [0xff; 16],
            };
            let mut owner = Owner::start(&mut storage, &mut ws);
            owner.update(&msg[..split]).unwrap();
            owner.update(&[]).unwrap();
            owner.update(&msg[split..]).unwrap();
            assert_eq!(owner.finalize(), expected, "len={n}, split={split}");
            check_clear(&storage, &ws);
        }
    }
}

#[test]
fn full_tag_and_abandoned_message_cleanup() {
    let key = [0x73; 32];
    let msg = [0xa7; 1519];
    let tag = crate::portable(&key, &msg);
    for changed in 0..=16 {
        let mut expected = tag;
        if let Some(byte) = expected.get_mut(changed) {
            *byte ^= 1;
        }
        let mut storage = key;
        let mut ws = Workspace::default();
        let mut m = Owner::start(&mut storage, &mut ws);
        m.update(&msg).unwrap();
        assert_eq!(m.verify(&expected), changed == 16);
        check_clear(&storage, &ws);
    }
    for unwind in [false, true] {
        let mut storage = key;
        let mut ws = Workspace::default();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut m = Owner::start(&mut storage, &mut ws);
            m.update(&msg).unwrap();
            if unwind {
                panic!("public fixture interruption");
            }
        }));
        assert_eq!(res.is_err(), unwind);
        check_clear(&storage, &ws);
    }
}

#[test]
fn length_rejection_does_not_change_state() {
    let mut key = [0xb5; 32];
    let mut ws = Workspace::default();
    let mut m = Owner::start(&mut key, &mut ws);
    m.update(&[0xcc; 1031]).unwrap();
    m.len = u64::MAX - 1;
    let before = (m.ws.acc, m.ws.tail, m.used, m.len);
    assert_eq!(m.update(&[1, 2]), Err("length"));
    assert_eq!((m.ws.acc, m.ws.tail, m.used, m.len), before);
    m.update(&[1]).unwrap();
    m.update(&[]).unwrap();
    assert_eq!(m.update(&[1]), Err("length"));
}

#[test]
fn precomputed_key_storage_cleared_in_place_even_on_unwind() {
    #[target_feature(enable = "avx2")]
    fn check(unwind: bool) {
        let mut p = [[[0xa5; 8]; 5]; 4];
        let mut t = [[_mm256_set1_epi8(-1); 5]; 5];
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _p = Powers(&mut p);
            let _t = TableGuard(&mut t);
            if unwind {
                panic!("public fixture interruption");
            }
        }));
        assert_eq!(res.is_err(), unwind);
        assert_eq!(p, [[[0; 8]; 5]; 4]);
        for v in t.into_iter().flatten() {
            assert_ne!(_mm256_testz_si256(v, v), 0);
        }
    }
    assert!(std::is_x86_feature_detected!("avx2"));
    // SAFETY: runtime AVX2 check above.
    unsafe {
        check(false);
        check(true);
    }
}
