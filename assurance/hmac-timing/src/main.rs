//! Bounded explicit-route observations, not proof of constant-time execution.
//! Every input is synthetic. Construction and finalization both remain measured.
mod routes;
use routes::{Algorithm, Result, Route};
use std::{hint::black_box, time::Instant};

const SAMPLES: usize = 512;
const REPEAT: usize = 4;

fn reference<A: Algorithm>(key: &[u8], output: &mut [u8]) -> Result<()> {
    let mut state = brynja_mac_hmac::Hmac::<A>::with_tag_length(key, output.len())
        .map_err(|error| format!("{error:?}"))?;
    state
        .update(&[0x37; 73])
        .map_err(|error| format!("{error:?}"))?;
    let _ = state
        .finalize_tag(output)
        .map_err(|error| format!("{error:?}"))?;
    Ok(())
}

fn operation<A: Algorithm>(
    route: &mut Route<A>,
    mode: &str,
    key: &[u8],
    candidate: &[u8],
    tag_bytes: usize,
) -> Result<()> {
    let mut destination = [0; 64];
    let matched = route.operation(
        key,
        (mode == "verify").then_some(candidate),
        &mut destination[..tag_bytes],
    )?;
    if black_box(matched) {
        return Err("invalid tag accepted".into());
    }
    black_box(destination);
    Ok(())
}

fn measure<A: Algorithm>(
    route: &mut Route<A>,
    mode: &str,
    key: &[u8],
    candidate: &[u8],
    tag_bytes: usize,
) -> Result<u128> {
    let start = Instant::now();
    for _ in 0..REPEAT {
        operation::<A>(route, mode, key, candidate, tag_bytes)?;
    }
    Ok(start.elapsed().as_nanos())
}

fn campaign<A: Algorithm>(
    identity: &str,
    route_name: &str,
    family: &str,
    smoke: bool,
) -> Result<()> {
    // For fractional general digests this is the largest whole-byte tag,
    // deliberately not an incorrectly rounded full tag.
    for tag_bytes in [16, A::TAG_BITS / 8] {
        let mut route = Route::<A>::new(route_name, family, tag_bytes)?;
        for key_bytes in [32, 200] {
            let key0 = [0x55; 200];
            let key1 = [0xaa; 200];
            let mut expected = [0; 64];
            reference::<A>(&key0[..key_bytes], &mut expected[..tag_bytes])?;
            let mut first = expected;
            let mut last = expected;
            first[0] ^= 1;
            last[tag_bytes - 1] ^= 1;
            // Prove the selected path computes both classes and rejects both
            // mismatch positions; a no-op/reject-all route cannot earn samples.
            for key in [&key0[..key_bytes], &key1[..key_bytes]] {
                let mut reference = [0; 64];
                let mut observed = [0; 64];
                self::reference::<A>(key, &mut reference[..tag_bytes])?;
                route.operation(key, None, &mut observed[..tag_bytes])?;
                if observed != reference
                    || !route.operation(
                        key,
                        Some(&reference[..tag_bytes]),
                        &mut observed[..tag_bytes],
                    )?
                {
                    return Err("selected route correctness preflight failed".into());
                }
            }
            for candidate in [&first, &last] {
                operation(
                    &mut route,
                    "verify",
                    &key0[..key_bytes],
                    &candidate[..tag_bytes],
                    tag_bytes,
                )?;
            }
            if smoke {
                continue;
            }
            // Two secret-value contrasts, holding all public lengths fixed:
            // first/last invalid byte, and two same-length key contents.
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
                        elapsed[class] = measure::<A>(
                            &mut route,
                            mode,
                            &key[..key_bytes],
                            &candidate[..tag_bytes],
                            tag_bytes,
                        )?;
                    }
                    if sample >= 32 {
                        println!(
                            "SAMPLE {identity} {mode} {key_bytes} {tag_bytes} {} {} {}",
                            sample - 32,
                            elapsed[0],
                            elapsed[1]
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    use brynja_mac_hmac::*;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 && !(args.len() == 3 && args[2] == "--smoke") {
        return Err("expected ROUTE FAMILY [--smoke]".into());
    }
    let route = &args[0];
    let family = &args[1];
    let smoke = args.len() == 3;
    if !matches!(family.as_str(), "all" | "sha256" | "sha512" | "keccak")
        || (matches!(
            route.as_str(),
            "static" | "runtime" | "linux-compiled" | "macos-compiled"
        ) && family == "all")
    {
        return Err("explicit accelerated family required".into());
    }
    let mut count = 0;
    macro_rules! run {
        ($algorithm:ty, $name:literal, $family:literal) => {
            if family == "all" || family == $family {
                campaign::<$algorithm>($name, route, $family, smoke)?;
                count += 1;
            }
        };
    }
    run!(Sha224, "sha224", "sha256");
    run!(Sha256, "sha256", "sha256");
    run!(Sha384, "sha384", "sha512");
    run!(Sha512, "sha512", "sha512");
    run!(Sha512_224, "sha512_224", "sha512");
    run!(Sha512_256, "sha512_256", "sha512");
    run!(Sha3_224, "sha3_224", "keccak");
    run!(Sha3_256, "sha3_256", "keccak");
    run!(Sha3_384, "sha3_384", "keccak");
    run!(Sha3_512, "sha3_512", "keccak");
    run!(Sha512T<129>, "general129", "sha512");
    run!(Sha512T<511>, "general511", "sha512");
    if smoke {
        println!("HMAC_TIMING_SMOKE {count} {route} {family}");
    } else {
        println!(
            "HMAC_TIMING_COMPLETE {count} {} 512 4 {route} {family}",
            count * 8
        );
    }
    Ok(())
}
