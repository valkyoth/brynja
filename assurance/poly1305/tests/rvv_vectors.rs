#![cfg(all(target_arch = "riscv64", target_os = "linux"))]

use brynja_mac_poly1305::{Error, OneTimeKey, rvv::Rvv};

fn decode(s: &str) -> Vec<u8> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty());
    pairs
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn check(cpu: &mut Rvv, key: [u8; 32], msg: &[u8], tag: [u8; 16], chunks: &[usize]) {
    for &chunk in chunks {
        let mut storage = key;
        let mut mac = OneTimeKey::from_rfc8439_key(&mut storage)
            .start_rvv(cpu)
            .unwrap();
        for bytes in msg.chunks(chunk) {
            mac.update(bytes).unwrap();
        }
        assert_eq!(mac.finalize().unwrap(), tag);
        assert_eq!(storage, [0; 32]);
    }
    for i in 0..=16 {
        let mut storage = key;
        let mut mac = OneTimeKey::from_rfc8439_key(&mut storage)
            .start_rvv(cpu)
            .unwrap();
        mac.update(msg).unwrap();
        let mut t = tag;
        if let Some(b) = t.get_mut(i) {
            *b ^= 1;
        }
        assert_eq!(
            mac.verify(&t),
            if i == 16 {
                Ok(())
            } else {
                Err(Error::Authentication)
            }
        );
        assert_eq!(storage, [0; 32]);
    }
}

#[test]
fn rfc_and_partitioned_long_updates() {
    let mut cpu = Rvv::probe().unwrap();
    let records = include_str!("../../../crates/brynja-mac-poly1305/tests/data/rfc8439.tsv");
    assert_eq!(records.lines().count(), 12);
    for row in records.lines() {
        let f: Vec<_> = row.split('\t').collect();
        check(
            &mut cpu,
            decode(f[1]).try_into().unwrap(),
            &decode(f[2]),
            decode(f[3]).try_into().unwrap(),
            &[1, 16, 17, 1024, 1500],
        );
    }
    for seed in [0u8, 1, 31, 127, 255] {
        let key = std::array::from_fn(|i| seed.wrapping_add(i as u8).wrapping_mul(19));
        for size in [
            63, 64, 65, 1023, 1024, 1025, 1039, 1040, 1500, 2049, 3000, 4096, 16384,
        ] {
            let msg: Vec<_> = (0..size)
                .map(|i| seed.wrapping_add(i as u8) ^ ((i >> 8) as u8))
                .collect();
            let mut storage = key;
            let mut mac = OneTimeKey::new(&mut storage).unwrap().start();
            mac.update(&msg).unwrap();
            check(
                &mut cpu,
                key,
                &msg,
                mac.finalize(),
                &[1, 17, 63, 1023, 1024, 1025, 1500, size],
            );
        }
    }
}
