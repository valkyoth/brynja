//! Throughput probe, not a side-channel test. Public fixtures only.
use brynja_chacha20_parallel_probe::record;
use brynja_cipher_chacha::ChaCha20;
use std::{hint::black_box, time::Instant};

const KEY: [u8; 32] = [0x53; 32];
const NONCE: [u8; 12] = [0xb9; 12];
const PAIRS: usize = 12;

fn apply<const PARALLEL: bool>(data: &mut [u8]) {
    if PARALLEL {
        record(black_box(&KEY), black_box(NONCE), 1, data).unwrap()
    } else {
        ChaCha20::new(black_box(&KEY), black_box(NONCE), 1)
            .apply_keystream_in_place(data)
            .unwrap();
    }
}

fn sample<const PARALLEL: bool>(data: &mut [u8], count: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..count {
        apply::<PARALLEL>(black_box(data));
        black_box(&*data);
    }
    start.elapsed().as_nanos()
}

fn main() {
    #[cfg(all(target_arch = "riscv64", target_os = "linux"))]
    if std::env::args().nth(1).as_deref() == Some("--require-no-v") {
        let mut data = [0xa5; 256];
        assert_eq!(
            brynja_chacha20_parallel_probe::try_record(&KEY, NONCE, 1, &mut data),
            None
        );
        assert_eq!(data, [0xa5; 256]);
        apply::<false>(&mut data);
        println!("RVV unavailable; candidate refused without mutation; scalar ran");
        return;
    }
    for size in [64, 255, 256, 257, 512, 1024, 1500, 4096, 16384] {
        let mut data: Vec<_> = (0..size).map(|i| (i * 17) as u8).collect();
        let mut expected = data.clone();
        apply::<false>(&mut expected);
        apply::<true>(&mut data);
        assert_eq!(data, expected);
        let count = 2 * (131072 / size); // even: both routes start from the same bytes
        sample::<false>(&mut data, count);
        sample::<true>(&mut data, count);
        let mut ratios = [0.0; PAIRS];
        for (pair, ratio) in ratios.iter_mut().enumerate() {
            let (s, p) = if pair % 2 == 0 {
                (
                    sample::<false>(&mut data, count),
                    sample::<true>(&mut data, count),
                )
            } else {
                let p = sample::<true>(&mut data, count);
                (sample::<false>(&mut data, count), p)
            };
            *ratio = s as f64 / p as f64;
            println!("pair={pair} bytes={size} repeats={count} scalar_ns={s} candidate_ns={p}");
        }
        ratios.sort_by(f64::total_cmp);
        println!(
            "bytes={size} groups={} median_speedup={:.3}",
            size / 256,
            (ratios[5] + ratios[6]) / 2.0
        );
    }
}
