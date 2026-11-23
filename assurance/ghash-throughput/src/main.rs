//! End-to-end single-owner throughput on deterministic public inputs only.
#![forbid(unsafe_code)]

use brynja_crypto::ghash::Ghash;
use std::{hint::black_box, time::Instant};

const KEY: [u8; 16] = 0xb83b533708bf535d0aa6e52980d53b78u128.to_be_bytes();
const CASES: [(usize, usize, usize); 4] = [
    (16, 16, 4096),
    (1024, 1024, 128),
    (16384, 16384, 8),
    (16384, 13, 8),
];

// Independent wire-order reference used before measurement, never in its timer.
fn reference(input: &[u8]) -> [u8; 16] {
    let mut state = 0u128;
    for block in input.as_chunks::<16>().0 {
        let x = state ^ u128::from_be_bytes(*block);
        let mut v = u128::from_be_bytes(KEY);
        state = 0;
        for i in (0..128).rev() {
            if x & (1 << i) != 0 {
                state ^= v;
            }
            v = (v >> 1) ^ if v & 1 != 0 { 0xe1 << 120 } else { 0 };
        }
    }
    state.to_be_bytes()
}

#[inline(never)]
fn message<const CHECK: bool>(input: &[u8], chunk: usize, expected: &[u8; 16]) {
    let (mut work, mut out) = ([0; 16], [0; 16]);
    let mut owner = Ghash::new(black_box(&KEY), &mut work, input.len() as u64);
    for part in input.chunks(chunk) {
        owner
            .update(black_box(part))
            .expect("bounded public fixture");
    }
    if CHECK {
        #[cfg(any(
            brynja_ghash_pclmul_evidence,
            brynja_ghash_pmull_evidence,
            brynja_ghash_rv64_evidence
        ))]
        assert_eq!(owner.native_blocks(), Ok((input.len() / 16) as u64));
    }
    let result = owner.finish(&mut out).expect("complete public fixture");
    if CHECK {
        assert_eq!(result.expose(), expected);
    }
    black_box(result.expose());
    result.clear();
}

fn main() {
    let mut seed = 0x6a09e667f3bcc909u64;
    let data: [u8; 16384] = std::array::from_fn(|_| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed.to_le_bytes()[0]
    });
    let route = if cfg!(any(
        brynja_ghash_pclmul_evidence,
        brynja_ghash_pmull_evidence,
        brynja_ghash_rv64_evidence
    )) {
        "candidate"
    } else {
        "portable"
    };
    for (size, chunk, repeats) in CASES {
        let input = &data[..size];
        let expected = reference(input);
        message::<true>(input, chunk, &expected);
        for _ in 0..repeats {
            message::<false>(input, chunk, &expected);
        }
        let start = Instant::now();
        for _ in 0..repeats {
            message::<false>(input, chunk, &expected);
        }
        let elapsed = start.elapsed().as_nanos();
        println!("{route} {size} {chunk} {repeats} {elapsed}");
    }
}
