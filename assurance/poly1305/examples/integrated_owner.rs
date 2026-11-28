//! Public fixture data; this compares complete checked-key messages, not startup.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use brynja_mac_poly1305::{OneTimeKey, execution::Avx2};
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use std::{hint::black_box, time::Instant};

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn record(cpu: Option<&mut Avx2>, key: &[u8; 32], msg: &[u8], chunk: usize) -> [u8; 16] {
    let mut storage = *key;
    let one = OneTimeKey::new(&mut storage).unwrap();
    if let Some(cpu) = cpu {
        let mut mac = one.start_avx2(cpu).unwrap();
        for part in msg.chunks(chunk) {
            mac.update(part).unwrap();
        }
        mac.finalize().unwrap()
    } else {
        let mut mac = one.start();
        for part in msg.chunks(chunk) {
            mac.update(part).unwrap();
        }
        mac.finalize()
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn main() {
    eprintln!("required AVX2: unsupported target");
    std::process::exit(2);
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn main() {
    let mut cpu = Avx2::probe().unwrap_or_else(|why| {
        eprintln!("required AVX2: {why:?}");
        std::process::exit(2)
    });
    let bench = std::env::args().nth(1).as_deref() == Some("--bench");
    let key = std::array::from_fn(|i| (i as u8).wrapping_mul(31));
    if bench {
        println!("bytes,chunk,pair,records,portable_ns,owner_ns");
    }
    for (size, chunk) in [16, 63, 64, 65, 256, 1023, 1024, 1025, 1500, 4096, 16384]
        .map(|n| (n, n))
        .into_iter()
        .chain([(16384, 1500), (16384, 17)])
    {
        let msg: Vec<_> = (0..size).map(|i| (i as u8).wrapping_mul(117)).collect();
        assert_eq!(
            record(Some(&mut cpu), &key, &msg, chunk),
            record(None, &key, &msg, chunk)
        );
        if !bench {
            continue;
        }
        let reps = 524288 / size;
        let mut batch = |native: bool| {
            let now = Instant::now();
            for _ in 0..reps {
                black_box(record(
                    if native { Some(&mut cpu) } else { None },
                    black_box(&key),
                    black_box(&msg),
                    black_box(chunk),
                ));
            }
            now.elapsed().as_nanos()
        };
        batch(false);
        batch(true);
        for pair in 0..12 {
            let (p, v) = if pair % 2 == 0 {
                (batch(false), batch(true))
            } else {
                let v = batch(true);
                (batch(false), v)
            };
            println!("{size},{chunk},{pair},{reps},{p},{v}");
        }
    }
}
