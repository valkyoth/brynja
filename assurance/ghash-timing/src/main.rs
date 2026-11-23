//! Local diagnostic using synthetic public test inputs only.
#![forbid(unsafe_code)]

use brynja_crypto::ghash::Ghash;
use std::{hint::black_box, time::Instant};

fn draw(seed: &mut u128) -> u128 {
    *seed ^= *seed << 23;
    *seed ^= *seed >> 17;
    *seed ^= *seed << 26;
    *seed
}

#[inline(never)]
fn timed(key: &[u8; 16], block: &[u8; 16]) -> u128 {
    let mut workspace = [0; 16];
    let mut output = [0; 16];
    let mut g = Ghash::new(black_box(key), &mut workspace, 256);
    let start = Instant::now();
    for _ in 0..16 {
        g.update(black_box(block)).unwrap();
    }
    // Prevent deferred computation. Timing includes finish and explicit
    // clearing; it does not include class generation or output formatting.
    let value = g.finish(&mut output).unwrap();
    black_box(value.expose());
    value.clear();
    start.elapsed().as_nanos()
}

fn main() {
    let mut output = [0; 16];
    let mut workspace = [0; 16];
    let one = (1u128 << 127).to_be_bytes();
    let mut g = Ghash::new(&one, &mut workspace, 16);
    g.update(&[0x69; 16]).unwrap();
    // Only available with the evidence cfg; selecting this diagnostic must
    // never silently benchmark the portable multiplication instead.
    #[cfg(any(
        feature = "pclmul-screen",
        feature = "pmull-screen",
        feature = "rv64-screen"
    ))]
    assert_eq!(g.native_blocks(), Ok(1));
    assert_eq!(g.finish(&mut output).unwrap().expose(), [0x69; 16]);

    let mut seed = 0xf71971c1a21f027bb72787d73928d81b;
    for mode in ["identical", "subkey", "block"] {
        let mut samples = Vec::with_capacity(2048);
        for i in 0..(2048 + 64) {
            let varied = draw(&mut seed).to_be_bytes();
            // Paired and balanced: the order reverses on the next pair.
            let mut ns = [0; 2];
            for slot in 0..2 {
                let class = slot ^ (i & 1);
                // Stage both labels into the same objects before the clock.
                let mut key = [0x39; 16];
                let mut block = [0xa7; 16];
                if class == 1 && mode == "subkey" {
                    key = varied;
                }
                if class == 1 && mode == "block" {
                    block = varied;
                }
                ns[class] = timed(black_box(&mut key), black_box(&mut block));
            }
            if i >= 64 {
                samples.push(ns);
            }
        }
        for [a, b] in samples {
            println!("{mode} {a} {b}");
        }
    }
}
