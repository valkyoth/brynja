//! Native paired throughput fixture; all operands are public test data.
use brynja_aead_chacha20poly1305::{Opener, Sealer, execution::Pair};
use std::{hint::black_box, time::Instant};

fn main() {
    let mut cpu = Pair::probe().unwrap_or_else(|e| {
        eprintln!("required pair: {e:?}");
        std::process::exit(2)
    });
    if std::env::args().nth(1).is_none() {
        return;
    }
    assert_eq!(std::env::args().skip(1).collect::<Vec<_>>(), ["--bench"]);
    println!("operation,bytes,pair,records,portable_ns,paired_ns");
    let aad = b"public sample header";
    let key = std::array::from_fn(|i| (i as u8).wrapping_mul(31));
    for size in [64usize, 256, 1024, 1500, 4096, 16384] {
        let reps = 524288 / size;
        let plain: Vec<_> = (0..size).map(|i| (i as u8).wrapping_mul(117)).collect();
        let mut work = vec![0; size];
        let mut dst = vec![0; size];
        let mut cipher = vec![0; size];
        let prefix = (size as u32).to_be_bytes();
        let mut portable =
            Sealer::from_reserved_range(&key, prefix, 0, (13 * reps + 1) as u64).unwrap();
        let mut native =
            Sealer::from_reserved_range(&key, prefix, (13 * reps + 1) as u64, (13 * reps) as u64)
                .unwrap();
        let (nonce, tag) = portable.seal(aad, &plain, &mut cipher, &mut work).unwrap();
        let rx = Opener::new(&key);
        for opening in [false, true] {
            let mut batch = |paired: bool| {
                macro_rules! timed {
                    ($op:expr) => {{
                        let start = Instant::now();
                        for _ in 0..reps {
                            black_box($op.unwrap());
                            black_box(&dst);
                        }
                        start.elapsed().as_nanos()
                    }};
                }
                if opening {
                    if paired {
                        let mut op = rx.with_pair(&mut cpu).unwrap();
                        timed!(op.open(
                            nonce,
                            black_box(aad),
                            &tag,
                            black_box(&cipher),
                            &mut dst,
                            &mut work
                        ))
                    } else {
                        timed!(rx.open(
                            nonce,
                            black_box(aad),
                            &tag,
                            black_box(&cipher),
                            &mut dst,
                            &mut work
                        ))
                    }
                } else if paired {
                    let mut op = native.with_pair(&mut cpu).unwrap();
                    timed!(op.seal(black_box(aad), black_box(&plain), &mut dst, &mut work))
                } else {
                    timed!(portable.seal(black_box(aad), black_box(&plain), &mut dst, &mut work))
                }
            };
            batch(false);
            batch(true);
            let name = if opening { "open" } else { "seal" };
            for pair in 0..12 {
                let (p, n) = if pair % 2 == 0 {
                    (batch(false), batch(true))
                } else {
                    let n = batch(true);
                    (batch(false), n)
                };
                println!("{name},{size},{pair},{reps},{p},{n}");
            }
            if opening {
                assert_eq!(dst, plain);
            }
            assert!(work.iter().all(|&b| b == 0));
        }
    }
}
