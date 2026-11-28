//! Unpublished arithmetic and streaming experiments. Public fixtures only.
#[cfg(target_arch = "x86_64")]
mod avx2 {
    mod admission;
    pub(super) use admission::Required;
    pub(super) mod stream;
    use std::arch::x86_64::*;
    type F = [u64; 5];
    const MASK: u64 = (1 << 26) - 1;

    fn limbs(x: u128) -> F {
        std::array::from_fn(|i| ((x >> (26 * i)) as u64) & MASK)
    }

    fn block(bytes: &[u8]) -> F {
        debug_assert!(!bytes.is_empty() && bytes.len() <= 16);
        let mut b = [0; 16];
        b[..bytes.len()].copy_from_slice(bytes);
        let mut m = limbs(u128::from_le_bytes(b));
        let bit = bytes.len() * 8;
        m[bit / 26] |= 1 << (bit % 26);
        m
    }

    fn reduce(mut x: F) -> F {
        for _ in 0..3 {
            let mut carry = 0;
            for limb in &mut x {
                let n = *limb + carry;
                *limb = n & MASK;
                carry = n >> 26;
            }
            x[0] += 5 * carry;
        }
        debug_assert!(x.iter().all(|&n| n <= MASK));
        x
    }

    fn add(x: F, y: F) -> F {
        std::array::from_fn(|i| x[i] + y[i])
    }

    fn mul(x: F, y: F) -> F {
        reduce(std::array::from_fn(|j| {
            (0..5)
                .map(|i| x[i] * y[(j + 5 - i) % 5] * if i > j { 5 } else { 1 })
                .sum()
        }))
    }

    #[target_feature(enable = "avx2")]
    fn pack(w: [u64; 4]) -> __m256i {
        _mm256_set_epi64x(w[3] as i64, w[2] as i64, w[1] as i64, w[0] as i64)
    }

    // Each lane computes a DIFFERENT block times a different power of r.
    // Factors <= 5*(2^26-1), block+state limbs < 2^27: both fit in u32.
    // Even the horizontal sum of four five-term columns fits in u64.
    #[inline(never)]
    #[target_feature(enable = "avx2")]
    fn group(h: F, bytes: &[u8; 64], weights: &[[__m256i; 5]; 5]) -> F {
        let blocks = bytes.as_chunks::<16>().0;
        let mut messages: [F; 4] = std::array::from_fn(|i| block(&blocks[i]));
        messages[0] = add(messages[0], h);
        let words: [_; 5] = std::array::from_fn(|i| pack(messages.map(|m| m[i])));
        reduce(weights.map(|row| {
            let sum = words
                .into_iter()
                .zip(row)
                .fold(_mm256_setzero_si256(), |acc, (x, y)| {
                    _mm256_add_epi64(acc, _mm256_mul_epu32(x, y))
                });
            _mm256_extract_epi64::<0>(sum) as u64
                + _mm256_extract_epi64::<1>(sum) as u64
                + _mm256_extract_epi64::<2>(sum) as u64
                + _mm256_extract_epi64::<3>(sum) as u64
        }))
    }

    #[target_feature(enable = "avx2")]
    pub(super) fn tag(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        let (raw, pad) = key.split_at(16);
        let r = limbs(
            u128::from_le_bytes(raw.try_into().unwrap())
                & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff,
        );
        let mut h = [0; 5];
        let (groups, tail) = msg.as_chunks::<64>();
        if !groups.is_empty() {
            // (h + m0)*r^4 + m1*r^3 + m2*r^2 + m3*r (mod 2^130-5).
            let r2 = mul(r, r);
            let powers = [mul(r2, r2), mul(r2, r), r2, r];
            let weights = std::array::from_fn(|j| {
                std::array::from_fn(|i| {
                    pack(powers.map(|p| p[(j + 5 - i) % 5] * if i > j { 5 } else { 1 }))
                })
            });
            for g in groups {
                h = group(h, g, &weights);
            }
        }
        for bytes in tail.chunks(16) {
            h = mul(add(h, block(bytes)), r);
        }
        // Subtract p before truncating to the low 128 bits.
        let mut q = 5;
        for limb in h {
            q = (limb + q) >> 26;
        }
        let low = h
            .iter()
            .rev()
            .fold(0u128, |x, &d| (x << 26) | u128::from(d));
        low.wrapping_add(u128::from(5 * q))
            .wrapping_add(u128::from_le_bytes(pad.try_into().unwrap()))
            .to_le_bytes()
    }
}

#[cfg(target_arch = "x86_64")]
fn checked_tag(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    assert!(
        std::is_x86_feature_detected!("avx2"),
        "native AVX2 required; no fallback"
    );
    // SAFETY: the running host reports AVX2. No raw pointer or external code.
    unsafe { avx2::tag(key, msg) }
}

#[cfg(target_arch = "x86_64")]
fn portable(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    use brynja_mac_poly1305::OneTimeKey;
    let mut storage = *key;
    let mut mac = OneTimeKey::from_rfc8439_key(&mut storage).start();
    mac.update(msg).unwrap();
    mac.finalize()
}

#[cfg(target_arch = "x86_64")]
fn throughput() {
    use std::{hint::black_box, time::Instant};
    let key = std::array::from_fn(|i| (i as u8).wrapping_mul(31));
    println!("bytes,pair,records,portable_ns,probe_ns");
    for size in [16, 63, 64, 65, 256, 1500, 4096, 16384] {
        let msg: Vec<_> = (0..size).map(|i| (i as u8).wrapping_mul(117)).collect();
        assert_eq!(portable(&key, &msg), checked_tag(&key, &msg));
        let reps = 524288 / size;
        let batch = |tag: fn(&[u8; 32], &[u8]) -> [u8; 16]| {
            let start = Instant::now();
            for _ in 0..reps {
                black_box(tag(black_box(&key), black_box(&msg)));
            }
            start.elapsed().as_nanos()
        };
        batch(portable);
        batch(checked_tag);
        for pair in 0..12 {
            let (p, v) = if pair % 2 == 0 {
                (batch(portable), batch(checked_tag))
            } else {
                let v = batch(checked_tag);
                (batch(portable), v)
            };
            println!("{size},{pair},{reps},{p},{v}");
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--check-admission") {
        let mut cpu = avx2::Required::probe().unwrap_or_else(|why| {
            eprintln!("required AVX2: {why}");
            std::process::exit(2)
        });
        let key = [0xab; 32];
        let message = [0x47; 4097];
        assert_eq!(
            avx2::stream::candidate(&mut cpu, &key, &message, 1500),
            portable(&key, &message)
        );
        println!("required AVX2: KAT and long-update comparison passed");
        return;
    }
    let mut cpu = avx2::Required::probe().expect("required AVX2 startup");
    // Public generated inputs, including every partial-block and group boundary.
    let decode = |field: &str| {
        let (pairs, rest) = field.as_bytes().as_chunks::<2>();
        assert!(rest.is_empty());
        pairs
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let cases = include_str!("../../../crates/brynja-mac-poly1305/tests/data/rfc8439.tsv");
    assert_eq!(cases.lines().count(), 12);
    for line in cases.lines() {
        let fields: [&str; 4] = line.split('\t').collect::<Vec<_>>().try_into().unwrap();
        let key = decode(fields[1]).try_into().unwrap();
        assert_eq!(
            checked_tag(&key, &decode(fields[2])).as_slice(),
            decode(fields[3]),
            "{}",
            fields[0]
        );
        assert_eq!(
            avx2::stream::candidate(&mut cpu, &key, &decode(fields[2]), 17).as_slice(),
            decode(fields[3]),
            "streaming {}",
            fields[0]
        );
    }
    let mut case_count = 0;
    for seed in 0..8u8 {
        let key = std::array::from_fn(|i| match seed {
            0 => 0,
            1 => 255,
            _ => (i as u8).wrapping_mul(31).wrapping_add(seed),
        });
        for len in (0..=257).chain([511, 512, 513, 1500, 4096, 16384]) {
            let msg: Vec<_> = (0..len)
                .map(|i| match seed {
                    0 | 1 => 255,
                    _ => (i as u8)
                        .wrapping_mul(117)
                        .wrapping_add((i >> 8) as u8 ^ seed),
                })
                .collect();
            assert_eq!(
                checked_tag(&key, &msg),
                portable(&key, &msg),
                "seed {seed}, length {len}"
            );
            case_count += 1;
            for chunk in [17, 1024, 1500, 16384] {
                assert_eq!(
                    avx2::stream::candidate(&mut cpu, &key, &msg, chunk),
                    portable(&key, &msg),
                    "streaming seed {seed}, length {len}, chunk {chunk}"
                );
            }
        }
    }
    println!("AVX2 four-block probe: 12 RFC vectors and {case_count} portable comparisons passed");
    println!(
        "Streaming probe: 12 RFC vectors and {} partitioned portable comparisons passed",
        case_count * 4
    );
    match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => (),
        [flag] if flag == "--bench" => throughput(),
        [flag] if flag == "--stream-bench" => avx2::stream::throughput(),
        _ => panic!("usage: four_block_probe [--bench|--stream-bench]"),
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!("This experiment requires native x86-64 AVX2");
    std::process::exit(2);
}
