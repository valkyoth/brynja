//! Unpublished experiment. Only public test data are admitted by the runner.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod neon_probe;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
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
    fn neon(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        // SAFETY: this function is compiled only for an AArch64 NEON target.
        unsafe { neon_probe::tag(key, msg) }
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
            if neon(&key, &data) != want || portable(&key, &data) != want {
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
        for size in [16, 31, 32, 33, 256, 1500, 4096, 16384] {
            let msg: Vec<_> = (0..size).map(|i| (i as u8).wrapping_mul(117)).collect();
            assert_eq!(neon(&key, &msg), portable(&key, &msg));
            let reps = 524288 / size;
            let batch = |tag: fn(&[u8; 32], &[u8]) -> [u8; 16]| {
                let start = Instant::now();
                for _ in 0..reps {
                    black_box(tag(black_box(&key), black_box(&msg)));
                }
                start.elapsed().as_nanos()
            };
            batch(portable);
            batch(neon);
            for i in 0..12 {
                let (p, v) = if i % 2 == 0 {
                    (batch(portable), batch(neon))
                } else {
                    let v = batch(neon);
                    (batch(portable), v)
                };
                println!("{size},{i},{reps},{p},{v}");
            }
        }
    } else {
        return Err("usage: neon_two_block [--bench]");
    }
    Ok(())
}

#[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
fn main() {
    eprintln!("AArch64 with NEON required");
    std::process::exit(2);
}
