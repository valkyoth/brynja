//! Synthetic inputs only; first label is balanced independently of pair parity.
#![forbid(unsafe_code)]

use brynja_crypto::ghash::Ghash;
use std::{hint::black_box, time::Instant};

fn draw(s: &mut u128) -> u128 {
    *s ^= *s << 23;
    *s ^= *s >> 17;
    *s ^= *s << 26;
    *s
}

#[inline(never)]
fn timed(key: &[u8; 16], block: &[u8; 16]) -> u128 {
    let (mut workspace, mut output) = ([0; 16], [0; 16]);
    let mut g = Ghash::new(black_box(key), &mut workspace, 256);
    let start = Instant::now();
    for _ in 0..16 {
        g.update(black_box(block)).unwrap();
    }
    let value = g.finish(&mut output).unwrap();
    black_box(value.expose());
    value.clear();
    start.elapsed().as_nanos()
}

fn main() {
    let mut work = [0; 16];
    let mut output = [0; 16];
    let key = (1u128 << 127).to_be_bytes();
    let mut g = Ghash::new(&key, &mut work, 16);
    g.update(&[0x69; 16]).unwrap();
    assert_eq!(g.native_blocks(), Ok(1));
    assert_eq!(g.finish(&mut output).unwrap().expose(), [0x69; 16]);

    let mut data = 0xf71971c1a21f027bb72787d73928d81b;
    let mut order = 0x4d6f_6465_6c73_u128;
    let (mut key, mut block) = ([0; 16], [0; 16]);
    // Hold one address for each input across both calls, including under LTO.
    let (key, block) = (black_box(&mut key), black_box(&mut block));
    for mode in ["identical", "subkey", "block"] {
        let mut rows = Vec::with_capacity(2048);
        for group in 0..528 {
            let bits = draw(&mut order);
            for i in 0..4 {
                let first = ((bits >> (i % 2)) as usize & 1) ^ (i / 2);
                let varied = draw(&mut data).to_be_bytes();
                let mut ns = [0; 2];
                for label in [first, 1 - first] {
                    *key = if label == 1 && mode == "subkey" {
                        varied
                    } else {
                        [0x39; 16]
                    };
                    *block = if label == 1 && mode == "block" {
                        varied
                    } else {
                        [0xa7; 16]
                    };
                    ns[label] = timed(black_box(&*key), black_box(&*block));
                }
                if group >= 16 {
                    rows.push((first, ns));
                }
            }
        }
        for (first, [a, b]) in rows {
            println!("{mode} {first} {a} {b}");
        }
    }
}
