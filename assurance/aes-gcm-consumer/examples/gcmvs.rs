//! Host-only replay of public NIST and generated differential records.
#![forbid(unsafe_code)]

use aes_gcm_consumer::crypto::aes_gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm, GcmError};
use std::io::{self, BufRead};

struct Case {
    key: Vec<u8>,
    iv: Vec<u8>,
    aad: Vec<u8>,
    ct: Vec<u8>,
    pt: Vec<u8>,
    tag: Vec<u8>,
}

fn hex(s: &str) -> Result<Vec<u8>, &'static str> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return Err("invalid hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex"))
        .collect()
}

fn check<const T: usize, const N: usize>(kind: &str, c: &Case) -> bool {
    let mut work = vec![0xa5; c.ct.len()];
    let mut output = vec![0x5a; c.ct.len()];
    let tag: &[u8; T] = c.tag.as_slice().try_into().unwrap();
    macro_rules! exercise {
        ($owner:ident, $size:literal) => {{
            let key = c.key.as_slice().try_into().unwrap();
            let mut schedule = [0; $size];
            match kind {
                "seal" | "seal-in-place" => {
                    macro_rules! seal {
                        ($sender:expr) => {{
                            if kind == "seal-in-place" {
                                output.copy_from_slice(&c.pt);
                                $sender.seal_next_in_place(&c.aad, &mut output, &mut work)
                            } else {
                                $sender.seal_next(&c.aad, &c.pt, &mut output, &mut work)
                            }
                        }};
                    }
                    // Public fixtures only: reconstruct precisely the published IV as
                    // a one-message reservation; do not add an arbitrary-IV sender API.
                    let matched = if N == 12 {
                        // This constructor returns the fixed-width owner. Handle it
                        // separately rather than narrowing the fixture's 64-bit suffix.
                        let first = u64::from_be_bytes(c.iv[4..].try_into().unwrap());
                        let mut sender = $owner::<T>::from_reserved_range(
                            key,
                            &mut schedule,
                            c.iv[..4].try_into().unwrap(),
                            first,
                            1,
                        )
                        .unwrap();
                        let result = seal!(sender);
                        result.is_ok_and(|(iv, t)| iv.as_slice() == c.iv && &t == tag)
                    } else {
                        let split = N.saturating_sub(4);
                        let mut suffix = [0; 4];
                        suffix[4 - (N - split)..].copy_from_slice(&c.iv[split..]);
                        let mut sender = $owner::<T, N>::from_reserved_invocations(
                            key,
                            &mut schedule,
                            &c.iv[..split],
                            u32::from_be_bytes(suffix),
                            1,
                        )
                        .unwrap();
                        let result = seal!(sender);
                        result.is_ok_and(|(iv, t)| iv.as_slice() == c.iv && &t == tag)
                    };
                    matched && output == c.ct
                }
                "open" | "reject" | "open-disjoint" | "reject-disjoint" => {
                    let receiver = $owner::<T>::for_open(key, &mut schedule).unwrap();
                    let disjoint = kind.ends_with("-disjoint");
                    let result = if disjoint {
                        receiver.open(&c.iv, &c.aad, tag, &c.ct, &mut output, &mut work)
                    } else {
                        output.copy_from_slice(&c.ct);
                        receiver.open_in_place(&c.iv, &c.aad, tag, &mut output, &mut work)
                    };
                    if kind.starts_with("reject") {
                        result == Err(GcmError::Authentication)
                            && if disjoint {
                                output.iter().all(|&x| x == 0x5a)
                            } else {
                                output == c.ct
                            }
                    } else {
                        result.is_ok() && output == c.pt
                    }
                }
                _ => false,
            }
        }};
    }
    let passed = match c.key.len() {
        16 => exercise!(Aes128Gcm, 176),
        24 => exercise!(Aes192Gcm, 208),
        32 => exercise!(Aes256Gcm, 240),
        _ => false,
    };
    passed && work.iter().all(|&x| x == 0)
}

fn row(line: &str) -> Result<usize, &'static str> {
    let fields: Vec<_> = line.split('\t').collect();
    let [kind, key, iv, aad, ct, pt, tag] = fields[..] else {
        return Err("invalid row");
    };
    let c = Case {
        key: hex(key)?,
        iv: hex(iv)?,
        aad: hex(aad)?,
        ct: hex(ct)?,
        pt: hex(pt)?,
        tag: hex(tag)?,
    };
    fn width<const T: usize>(kind: &str, c: &Case) -> bool {
        match c.iv.len() {
            1 => check::<T, 1>(kind, c),
            3 => check::<T, 3>(kind, c),
            4 => check::<T, 4>(kind, c),
            5 => check::<T, 5>(kind, c),
            8 => check::<T, 8>(kind, c),
            11 => check::<T, 11>(kind, c),
            12 => check::<T, 12>(kind, c),
            13 => check::<T, 13>(kind, c),
            15 => check::<T, 15>(kind, c),
            16 => check::<T, 16>(kind, c),
            17 => check::<T, 17>(kind, c),
            128 => check::<T, 128>(kind, c),
            129 => check::<T, 129>(kind, c),
            _ => false,
        }
    }
    let passed = match c.tag.len() {
        12 => width::<12>(kind, &c),
        13 => width::<13>(kind, &c),
        14 => width::<14>(kind, &c),
        15 => width::<15>(kind, &c),
        16 => width::<16>(kind, &c),
        _ => false,
    };
    if !passed {
        return Err("wrong result, output or scratch");
    }
    match kind {
        "seal" | "seal-in-place" => Ok(0),
        "open" | "open-disjoint" => Ok(1),
        "reject" | "reject-disjoint" => Ok(2),
        _ => Err("unknown operation"),
    }
}

fn main() {
    let mut counts = [0usize; 3];
    for (i, line) in io::stdin().lock().lines().enumerate() {
        let kind =
            row(&line.expect("read fixture")).unwrap_or_else(|err| panic!("case {}: {err}", i + 1));
        counts[kind] += 1;
    }
    println!("seal={} open={} reject={}", counts[0], counts[1], counts[2]);
}
