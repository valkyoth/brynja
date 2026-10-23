//! Synthetic fixed-public-length contrasts; not a side-channel proof.
mod routes;
use routes::{Result, Route, Tags};
use std::{hint::black_box, time::Instant};
const SAMPLES: usize = 512;
const REPEAT: usize = 4;

fn operation(
    route: &mut Route,
    mode: &str,
    key: &[u8],
    candidate: &Tags,
    bytes: usize,
) -> Result<()> {
    let mut out = [[0; 20]; 8];
    let matched = route.operation(
        key,
        (mode == "verify").then_some(candidate),
        &mut out,
        bytes,
    )?;
    if black_box(matched) {
        return Err("invalid tag accepted".into());
    }
    black_box(out);
    Ok(())
}
fn measure(
    route: &mut Route,
    mode: &str,
    key: &[u8],
    candidate: &Tags,
    bytes: usize,
) -> Result<u128> {
    let start = Instant::now();
    for _ in 0..REPEAT {
        operation(route, mode, key, candidate, bytes)?;
    }
    Ok(start.elapsed().as_nanos())
}
fn reference(family: &str, key: &[u8], bytes: usize, lanes: usize) -> Result<Tags> {
    match family {
        "sha1" => routes::reference::<brynja_legacy_hmac::Sha1>(key, bytes, lanes),
        "md5" => routes::reference::<brynja_legacy_hmac::Md5>(key, bytes, lanes),
        _ => Err("unsupported family".into()),
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 && !(args.len() == 3 && args[2] == "--smoke") {
        return Err("expected ROUTE FAMILY [--smoke]".into());
    }
    let (route_name, family) = (&args[0], &args[1]);
    let smoke = args.len() == 3;
    let full = match family.as_str() {
        "sha1" => 20,
        "md5" => 16,
        _ => return Err("unsupported family".into()),
    };
    let mut observed_lanes = 0;
    for bytes in [10, full] {
        let mut route = Route::new(route_name, family, bytes)?;
        let lanes = route.lanes();
        if !matches!(lanes, 1 | 4 | 8) || (observed_lanes != 0 && observed_lanes != lanes) {
            return Err("invalid route width".into());
        }
        observed_lanes = lanes;
        for key_bytes in [32, 200] {
            let key0 = [0x55; 200];
            let key1 = [0xaa; 200];
            let expected = reference(family, &key0[..key_bytes], bytes, lanes)?;
            let mut first = expected;
            let mut last = expected;
            first[0][0] ^= 1;
            last[lanes - 1][bytes - 1] ^= 1;
            // Both key classes must compute correct tags and accept correct
            // candidates; both invalid classes must reject before sampling.
            for key in [&key0[..key_bytes], &key1[..key_bytes]] {
                let expected = reference(family, key, bytes, lanes)?;
                let mut actual = [[0; 20]; 8];
                route.operation(key, None, &mut actual, bytes)?;
                if actual != expected
                    || !route.operation(key, Some(&expected), &mut actual, bytes)?
                {
                    return Err("selected route correctness preflight failed".into());
                }
            }
            for candidate in [&first, &last] {
                operation(&mut route, "verify", &key0[..key_bytes], candidate, bytes)?;
            }
            if smoke {
                continue;
            }
            for mode in ["verify", "key"] {
                let mut order = 0x9e37_79b9_u32;
                for sample in 0..SAMPLES + 32 {
                    order ^= order << 13;
                    order ^= order >> 17;
                    order ^= order << 5;
                    let mut elapsed = [0; 2];
                    for class in [usize::from(order & 1 != 0), usize::from(order & 1 == 0)] {
                        let key = if mode == "key" && class == 1 {
                            &key1
                        } else {
                            &key0
                        };
                        let candidate = if class == 0 { &first } else { &last };
                        elapsed[class] =
                            measure(&mut route, mode, &key[..key_bytes], candidate, bytes)?;
                    }
                    if sample >= 32 {
                        println!(
                            "SAMPLE {family} {mode} {key_bytes} {bytes} {} {} {}",
                            sample - 32,
                            elapsed[0],
                            elapsed[1]
                        );
                    }
                }
            }
        }
    }
    if smoke {
        println!("LEGACY_HMAC_TIMING_SMOKE {route_name} {family} {observed_lanes}");
    } else {
        println!("LEGACY_HMAC_TIMING_COMPLETE {route_name} {family} {observed_lanes} 8 512 4");
    }
    Ok(())
}
