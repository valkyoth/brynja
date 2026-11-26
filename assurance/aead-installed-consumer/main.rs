//! Replays PUBLIC NIST worked examples. Reconstructing the same key/IV for
//! different test layouts is for known answers only, never a sending policy.
#![forbid(unsafe_code)]

#[cfg(feature = "direct")]
use subject as crypto;
#[cfg(feature = "facade")]
use subject::crypto;

fn reservation(iv: [u8; 12]) -> ([u8; 4], u64) {
    let [a, b, c, d, suffix @ ..] = iv;
    ([a, b, c, d], u64::from_be_bytes(suffix))
}

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    let (pairs, tail) = s.as_bytes().as_chunks::<2>();
    assert!(tail.is_empty());
    pairs
        .iter()
        .map(|p| u8::from_str_radix(str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

struct Case {
    key: Vec<u8>,
    iv: [u8; 12],
    aad: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    tag: Vec<u8>,
}

#[cfg(feature = "aes-gcm")]
fn exercise<const T: usize>(c: &Case) {
    use crypto::aes_gcm::GcmError;
    #[cfg(feature = "native")]
    use crypto::aes_gcm::execution::{Aes128Gcm, Aes192Gcm, Aes256Gcm, AesPair};
    #[cfg(not(feature = "native"))]
    use crypto::aes_gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm};
    macro_rules! width {
        ($owner:ident, $size:literal) => {{
            let key = c.key.as_slice().try_into().unwrap();
            let expected: [u8; T] = c.tag[..T].try_into().unwrap();
            for inplace in [false, true] {
                let mut schedule = [0xa5; $size];
                let (prefix, counter) = reservation(c.iv);
                #[cfg(feature = "native")]
                let pair = AesPair::require().expect("required native pair");
                #[cfg(feature = "native")]
                let owner =
                    $owner::<T>::from_reserved_range(&pair, key, &mut schedule, prefix, counter, 1);
                #[cfg(not(feature = "native"))]
                let owner =
                    $owner::<T>::from_reserved_range(key, &mut schedule, prefix, counter, 1);
                let mut owner = owner.unwrap();
                let mut out = c.pt.clone();
                let mut work = vec![0xa5; out.len()];
                let issued = if inplace {
                    owner.seal_next_in_place(&c.aad, &mut out, &mut work)
                } else {
                    out.fill(0x5a);
                    owner.seal_next(&c.aad, &c.pt, &mut out, &mut work)
                };
                assert_eq!(issued, Ok((c.iv, expected)));
                assert_eq!(out, c.ct);
                assert!(work.iter().all(|b| *b == 0));
                // Exhaustion is pre-admission: even scratch is untouched.
                work.fill(0xa5);
                assert_eq!(
                    owner.seal_next_in_place(&c.aad, &mut out, &mut work),
                    Err(GcmError::Exhausted)
                );
                assert_eq!(out, c.ct);
                assert!(work.iter().all(|b| *b == 0xa5));
                let mut reject = |iv, aad: &[u8], ct: &[u8], tag| {
                    work.fill(0xa5);
                    if inplace {
                        out.copy_from_slice(ct);
                        assert_eq!(
                            owner.open_in_place(&iv, aad, &tag, &mut out, &mut work),
                            Err(GcmError::Authentication)
                        );
                        assert_eq!(out, ct);
                    } else {
                        out.fill(0x5a);
                        assert_eq!(
                            owner.open(&iv, aad, &tag, ct, &mut out, &mut work),
                            Err(GcmError::Authentication)
                        );
                        assert!(out.iter().all(|b| *b == 0x5a));
                    }
                    assert!(work.iter().all(|b| *b == 0));
                };
                for i in 0..T {
                    let mut bad = expected;
                    bad[i] ^= 1;
                    reject(c.iv, &c.aad, &c.ct, bad);
                }
                let mut aad = c.aad.clone();
                aad.push(0);
                reject(c.iv, &aad, &c.ct, expected);
                let mut iv = c.iv;
                iv[11] ^= 1;
                reject(iv, &c.aad, &c.ct, expected);
                let mut ct = c.ct.clone();
                if let Some(first) = ct.first_mut() {
                    *first ^= 1;
                    reject(c.iv, &c.aad, &ct, expected);
                }
                work.fill(0xa5);
                if inplace {
                    out.copy_from_slice(&c.ct);
                    owner
                        .open_in_place(&c.iv, &c.aad, &expected, &mut out, &mut work)
                        .unwrap();
                } else {
                    out.fill(0x5a);
                    owner
                        .open(&c.iv, &c.aad, &expected, &c.ct, &mut out, &mut work)
                        .unwrap();
                }
                assert_eq!(out, c.pt);
                assert!(work.iter().all(|b| *b == 0));
                drop(owner);
                assert_eq!(schedule, [0; $size]);
            }
        }};
    }
    match c.key.len() {
        16 => width!(Aes128Gcm, 176),
        24 => width!(Aes192Gcm, 208),
        32 => width!(Aes256Gcm, 240),
        _ => unreachable!(),
    }
}

#[cfg(feature = "gmac")]
fn exercise<const T: usize>(c: &Case) {
    #[cfg(feature = "native")]
    use crypto::gmac::execution::{Aes128Gmac, Aes192Gmac, Aes256Gmac, AesPair};
    #[cfg(not(feature = "native"))]
    use crypto::gmac::{Aes128Gmac, Aes192Gmac, Aes256Gmac};
    use crypto::gmac::{GmacError, GmacTag};
    assert!(c.pt.is_empty() && c.ct.is_empty());
    macro_rules! width {
        ($owner:ident, $size:literal) => {{
            let key = c.key.as_slice().try_into().unwrap();
            let mut schedule = [0xa5; $size];
            let (prefix, counter) = reservation(c.iv);
            #[cfg(feature = "native")]
            let pair = AesPair::require().expect("required native pair");
            #[cfg(feature = "native")]
            let owner =
                $owner::<T>::from_reserved_range(&pair, key, &mut schedule, prefix, counter, 1);
            #[cfg(not(feature = "native"))]
            let owner = $owner::<T>::from_reserved_range(key, &mut schedule, prefix, counter, 1);
            let mut owner = owner.unwrap();
            let (iv, tag) = owner.authenticate_next(&c.aad).unwrap();
            assert_eq!(iv, c.iv);
            assert_eq!(tag.as_bytes().as_slice(), &c.tag[..T]);
            assert!(matches!(
                owner.authenticate_next(&c.aad),
                Err(GmacError::Exhausted)
            ));
            for i in 0..T {
                let mut bad = *tag.as_bytes();
                bad[i] ^= 1;
                assert_eq!(
                    owner.verify(&iv, &c.aad, &GmacTag::from_bytes(bad)),
                    Err(GmacError::Authentication)
                );
            }
            let mut aad = c.aad.clone();
            aad.push(0);
            assert_eq!(
                owner.verify(&iv, &aad, &tag),
                Err(GmacError::Authentication)
            );
            let mut wrong_iv = iv;
            wrong_iv[11] ^= 1;
            assert_eq!(
                owner.verify(&wrong_iv, &c.aad, &tag),
                Err(GmacError::Authentication)
            );
            owner.verify(&iv, &c.aad, &tag).unwrap();
            drop(owner);
            assert_eq!(schedule, [0; $size]);
        }};
    }
    match c.key.len() {
        16 => width!(Aes128Gmac, 176),
        24 => width!(Aes192Gmac, 208),
        32 => width!(Aes256Gmac, 240),
        _ => unreachable!(),
    }
}

fn main() {
    let mut counts = [0; 3];
    for row in include_str!("nist-worked.txt").lines() {
        let [width, _, k, iv, aad, pt, ct, tag]: [&str; 8] = row
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let c = Case {
            key: hex(k),
            iv: hex(iv).try_into().unwrap(),
            aad: hex(aad),
            pt: hex(pt),
            ct: hex(ct),
            tag: hex(tag),
        };
        #[cfg(feature = "gmac")]
        if !c.pt.is_empty() {
            continue;
        }
        let slot = match width {
            "128" => 0,
            "192" => 1,
            "256" => 2,
            _ => unreachable!(),
        };
        exercise::<12>(&c);
        counts[slot] += 1;
        if c.tag.len() == 16 {
            exercise::<13>(&c);
            exercise::<14>(&c);
            exercise::<15>(&c);
            exercise::<16>(&c);
            counts[slot] += 4;
        }
    }
    assert_eq!(
        counts,
        if cfg!(feature = "gmac") {
            [10; 3]
        } else {
            [26; 3]
        }
    );
    println!("INSTALLED_CONSUMER_PASS {counts:?}");
}
