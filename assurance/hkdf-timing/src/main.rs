//! Synthetic fixed-length secret contrasts; an observation, not a timing proof.
#![forbid(unsafe_code)]

#[cfg(any(
    all(feature = "modern", feature = "legacy"),
    not(any(feature = "modern", feature = "legacy"))
))]
compile_error!("select exactly one HKDF family");

use std::{fmt::Write, hint::black_box, time::Instant};
type Result<T> = std::result::Result<T, String>;
const SAMPLES: usize = 512;
const REPEAT: usize = 4;

trait Scheme {
    const WIDTH: usize;
    fn extract(salt: &[u8], ikm: &[u8], observe: impl FnMut(&[u8])) -> Result<()>;
    fn import(secret: &[u8], observe: impl FnMut(&[u8])) -> Result<()>;
    fn expand(secret: &[u8], label: bool, observe: impl FnMut(&[u8])) -> Result<()>;
}

#[cfg(feature = "modern")]
struct Modern<A>(std::marker::PhantomData<A>);
#[cfg(feature = "modern")]
impl<A: brynja_crypto::hkdf::Algorithm> Scheme for Modern<A> {
    const WIDTH: usize = A::TAG_BYTES;
    fn extract(salt: &[u8], ikm: &[u8], mut observe: impl FnMut(&[u8])) -> Result<()> {
        let mut storage = [0; 64];
        let prk =
            brynja_crypto::hkdf::Prk::<A>::extract(Some(salt), ikm, &mut storage[..Self::WIDTH])
                .map_err(|e| format!("{e:?}"))?;
        observe(prk.expose());
        Ok(())
    }
    fn import(secret: &[u8], mut observe: impl FnMut(&[u8])) -> Result<()> {
        let mut storage = [0; 200];
        let prk = brynja_crypto::hkdf::Prk::<A>::import(secret, &mut storage[..secret.len()])
            .map_err(|e| format!("{e:?}"))?;
        observe(prk.expose());
        Ok(())
    }
    fn expand(secret: &[u8], label: bool, mut observe: impl FnMut(&[u8])) -> Result<()> {
        let mut storage = [0; 200];
        let prk = brynja_crypto::hkdf::Prk::<A>::import(secret, &mut storage[..secret.len()])
            .map_err(|e| format!("{e:?}"))?;
        let mut output = [0; 135];
        let output = &mut output[..2 * Self::WIDTH + 7];
        let key = if label {
            prk.expand_label(b"key", &[0x37; 48], output)
        } else {
            prk.expand(&[0x37; 48], output)
        }
        .map_err(|e| format!("{e:?}"))?;
        observe(key.expose());
        Ok(())
    }
}

#[cfg(feature = "legacy")]
struct Legacy;
#[cfg(feature = "legacy")]
impl Scheme for Legacy {
    const WIDTH: usize = 20;
    fn extract(salt: &[u8], ikm: &[u8], mut observe: impl FnMut(&[u8])) -> Result<()> {
        use brynja_legacy_hkdf::{LegacyUse, Sha1Prk};
        let mut storage = [0; 20];
        let prk = Sha1Prk::extract(LegacyUse::acknowledge(), Some(salt), ikm, &mut storage)
            .map_err(|e| format!("{e:?}"))?;
        observe(prk.expose());
        Ok(())
    }
    fn import(secret: &[u8], mut observe: impl FnMut(&[u8])) -> Result<()> {
        use brynja_legacy_hkdf::{LegacyUse, Sha1Prk};
        let mut storage = [0; 200];
        let prk = Sha1Prk::import(
            LegacyUse::acknowledge(),
            secret,
            &mut storage[..secret.len()],
        )
        .map_err(|e| format!("{e:?}"))?;
        observe(prk.expose());
        Ok(())
    }
    fn expand(secret: &[u8], label: bool, mut observe: impl FnMut(&[u8])) -> Result<()> {
        use brynja_legacy_hkdf::{LegacyUse, Sha1Prk};
        if label {
            return Err("legacy labels are forbidden".into());
        }
        let mut storage = [0; 200];
        let prk = Sha1Prk::import(
            LegacyUse::acknowledge(),
            secret,
            &mut storage[..secret.len()],
        )
        .map_err(|e| format!("{e:?}"))?;
        let mut output = [0; 47];
        let key = prk
            .expand(&[0x37; 48], &mut output)
            .map_err(|e| format!("{e:?}"))?;
        observe(key.expose());
        Ok(())
    }
}

fn operation<A: Scheme>(mode: &str, secret: &[u8; 200], observe: impl FnMut(&[u8])) -> Result<()> {
    match mode {
        "extract-ikm" => A::extract(&[0x37; 32], &secret[..64], observe),
        "extract-salt" => A::extract(secret, &[0x37; 64], observe),
        "import-long" => A::import(secret, observe),
        "expand" => A::expand(&secret[..A::WIDTH], false, observe),
        "expand-long" => A::expand(secret, false, observe),
        "label" => A::expand(&secret[..A::WIDTH], true, observe),
        _ => Err("unknown operation".into()),
    }
}

fn measure<A: Scheme>(mode: &str, secret: &[u8; 200]) -> Result<u128> {
    let start = Instant::now();
    for _ in 0..REPEAT {
        operation::<A>(black_box(mode), black_box(secret), |bytes| {
            black_box(bytes);
        })?;
    }
    Ok(start.elapsed().as_nanos())
}

fn campaign<A: Scheme>(
    name: &str,
    label: bool,
    preflight: bool,
    records: &mut Vec<String>,
) -> Result<()> {
    let secrets = [[0; 200], [0xff; 200]];
    let modes = [
        "extract-ikm",
        "extract-salt",
        "import-long",
        "expand",
        "expand-long",
        "label",
    ];
    for mode in &modes[..if label { 6 } else { 5 }] {
        if preflight {
            for (class, secret) in secrets.iter().enumerate() {
                let mut hex = String::new();
                operation::<A>(mode, secret, |bytes| {
                    for byte in bytes {
                        write!(hex, "{byte:02x}").expect("String write");
                    }
                })?;
                records.push(format!("VECTOR {name} {mode} {class} {hex}"));
            }
            continue;
        }
        // Each pair has both classes. Consecutive pairs reverse their order,
        // giving exactly 256 AB and 256 BA pairs after 32 discarded warmups.
        for sample in 0..SAMPLES + 32 {
            let first = sample % 2;
            let mut elapsed = [0; 2];
            for class in [first, 1 - first] {
                elapsed[class] = measure::<A>(mode, &secrets[class])?;
            }
            if sample >= 32 {
                records.push(format!(
                    "SAMPLE {name} {mode} {} {} {}",
                    sample - 32,
                    elapsed[0],
                    elapsed[1]
                ));
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 || !matches!(args[0].as_str(), "preflight" | "measure") {
        return Err("expected preflight or measure".into());
    }
    let preflight = args[0] == "preflight";
    // No stdout I/O during measurement. Records contain synthetic data only.
    let mut records = Vec::new();
    #[cfg(feature = "modern")]
    {
        use brynja_crypto::hkdf::*;
        campaign::<Modern<Sha224>>("sha224", true, preflight, &mut records)?;
        campaign::<Modern<Sha256>>("sha256", true, preflight, &mut records)?;
        campaign::<Modern<Sha384>>("sha384", true, preflight, &mut records)?;
        campaign::<Modern<Sha512>>("sha512", true, preflight, &mut records)?;
        campaign::<Modern<Sha512_224>>("sha512_224", true, preflight, &mut records)?;
        campaign::<Modern<Sha512_256>>("sha512_256", true, preflight, &mut records)?;
    }
    #[cfg(feature = "legacy")]
    campaign::<Legacy>("sha1", false, preflight, &mut records)?;
    for record in records {
        println!("{record}");
    }
    println!("HKDF_TIMING_END {}", args[0]);
    Ok(())
}
