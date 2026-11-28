//! Unpublished experiment. Only public test data are admitted by the runner.
#[cfg(all(target_arch = "riscv64", target_os = "linux", target_endian = "little"))]
mod field;

#[cfg(all(target_arch = "riscv64", target_os = "linux", target_endian = "little"))]
fn main() -> Result<(), &'static str> {
    use brynja_mac_poly1305::OneTimeKey;
    use std::{
        hint::black_box,
        io::{self, BufRead},
        time::Instant,
    };

    fn portable(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        let mut storage = *key;
        let mut mac = OneTimeKey::from_rfc8439_key(&mut storage).start();
        mac.update(msg).unwrap();
        mac.finalize()
    }
    fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
        let (pairs, tail) = s.as_bytes().as_chunks::<2>();
        if !tail.is_empty() {
            return Err("bad input");
        }
        pairs
            .iter()
            .map(|p| {
                u8::from_str_radix(std::str::from_utf8(p).map_err(|_| "bad input")?, 16)
                    .map_err(|_| "bad input")
            })
            .collect()
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    let Some(cpu) = field::Vector::detect() else {
        eprintln!("RVV unavailable; no candidate run");
        std::process::exit(2);
    };
    if args.is_empty() {
        let mut count = 0;
        for line in io::stdin().lock().lines() {
            let line = line.map_err(|_| "bad input")?;
            let mut row = line.split('\t');
            let key = decode(row.next().ok_or("bad input")?)?
                .try_into()
                .map_err(|_| "bad key")?;
            let data = decode(row.next().ok_or("bad input")?)?;
            let want: [u8; 16] = decode(row.next().ok_or("bad input")?)?
                .try_into()
                .map_err(|_| "bad tag")?;
            if row.next().is_some() {
                return Err("bad input");
            }
            if cpu.tag(&key, &data) != want || portable(&key, &data) != want {
                return Err("vector mismatch");
            }
            count += 1;
        }
        if count == 0 {
            return Err("empty corpus");
        }
        println!("matched {count} public vectors");
    } else if args == ["--bench"] {
        let key = core::array::from_fn(|i| (i as u8).wrapping_mul(31));
        println!("bytes,pair,records,portable_ns,probe_ns");
        for size in [16, 63, 64, 65, 256, 1500, 4096, 16384] {
            let msg: Vec<_> = (0..size).map(|i| (i as u8).wrapping_mul(117)).collect();
            assert_eq!(cpu.tag(&key, &msg), portable(&key, &msg));
            let reps = 524288 / size;
            let batch = |vector: bool| {
                let start = Instant::now();
                for _ in 0..reps {
                    let (k, m) = (black_box(&key), black_box(msg.as_slice()));
                    black_box(if vector {
                        cpu.tag(k, m)
                    } else {
                        portable(k, m)
                    });
                }
                start.elapsed().as_nanos()
            };
            batch(false);
            batch(true);
            for i in 0..12 {
                let (p, v) = if i % 2 == 0 {
                    (batch(false), batch(true))
                } else {
                    let v = batch(true);
                    (batch(false), v)
                };
                println!("{size},{i},{reps},{p},{v}");
            }
        }
    } else {
        return Err("usage: rvv_four_block [--bench]");
    }
    Ok(())
}

#[cfg(not(all(target_arch = "riscv64", target_os = "linux", target_endian = "little")))]
fn main() {
    eprintln!("little-endian Linux RV64 with V required");
    std::process::exit(2);
}
