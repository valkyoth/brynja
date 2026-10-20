//! Bounded portable observations, not proof of constant-time execution.
//! Every input is synthetic. Construction and finalization both remain measured.
use brynja_mac_hmac::{Algorithm, Error, Hmac};
use std::{hint::black_box, time::Instant};

const SAMPLES: usize = 512;
const REPEAT: usize = 4;

fn operation<A: Algorithm>(
    mode: &str,
    key: &[u8],
    candidate: &[u8],
    tag_bytes: usize,
) -> Result<(), Error> {
    let mut state = Hmac::<A>::with_tag_length(black_box(key), tag_bytes)?;
    state.update(black_box(&[0x37; 73]))?;
    if mode == "verify" {
        let matched = state.verify(black_box(candidate))?.expose_public();
        if black_box(matched) {
            return Err(Error::SecretMemory);
        }
    } else {
        let mut destination = [0; 64];
        let tag = state.finalize_tag(black_box(&mut destination[..tag_bytes]))?;
        black_box(tag.as_bytes());
    }
    Ok(())
}

fn measure<A: Algorithm>(
    mode: &str,
    key: &[u8],
    candidate: &[u8],
    tag_bytes: usize,
) -> Result<u128, Error> {
    let start = Instant::now();
    for _ in 0..REPEAT {
        operation::<A>(mode, key, candidate, tag_bytes)?;
    }
    Ok(start.elapsed().as_nanos())
}

fn campaign<A: Algorithm>(identity: &str) -> Result<(), Error> {
    // For fractional general digests this is the largest whole-byte tag,
    // deliberately not an incorrectly rounded full tag.
    for tag_bytes in [16, A::TAG_BITS / 8] {
        for key_bytes in [32, 200] {
            let key0 = [0x55; 200];
            let key1 = [0xaa; 200];
            let mut expected = [0; 64];
            let mut state = Hmac::<A>::with_tag_length(&key0[..key_bytes], tag_bytes)?;
            state.update(&[0x37; 73])?;
            let _ = state.finalize_tag(&mut expected[..tag_bytes])?;
            let mut first = expected;
            let mut last = expected;
            first[0] ^= 1;
            last[tag_bytes - 1] ^= 1;
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

fn main() -> Result<(), Error> {
    use brynja_mac_hmac::*;
    campaign::<Sha224>("sha224")?;
    campaign::<Sha256>("sha256")?;
    campaign::<Sha384>("sha384")?;
    campaign::<Sha512>("sha512")?;
    campaign::<Sha512_224>("sha512_224")?;
    campaign::<Sha512_256>("sha512_256")?;
    campaign::<Sha3_224>("sha3_224")?;
    campaign::<Sha3_256>("sha3_256")?;
    campaign::<Sha3_384>("sha3_384")?;
    campaign::<Sha3_512>("sha3_512")?;
    campaign::<Sha512T<129>>("general129")?;
    campaign::<Sha512T<511>>("general511")?;
    println!("HMAC_TIMING_COMPLETE 12 96 512 4 portable");
    Ok(())
}
