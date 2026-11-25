//! Offline downstream timing fixture. All keys and inputs are synthetic.
#![forbid(unsafe_code)]

use brynja_crypto::{aes_gcm as g, gmac as m};
use std::{hint::black_box, time::Instant};

const N: usize = 33;
const REPS: usize = 4;

fn campaign(name: &str, mut sample: impl FnMut(bool) -> u128) {
    let mut rows = Vec::with_capacity(1024);
    let mut state = 0x84a7_c953u32;
    let mut first = false;
    for i in 0..1056 {
        if i % 2 == 0 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            first = state & 1 != 0;
        } else {
            first = !first;
        }
        let a = sample(black_box(first));
        let b = sample(black_box(!first));
        if i >= 32 {
            let (zero, one) = if first { (b, a) } else { (a, b) };
            rows.push((first as u8, zero, one));
        }
    }
    for (i, (first, a, b)) in rows.into_iter().enumerate() {
        println!("{name} {i} {first} {a} {b}");
    }
}

macro_rules! width {
    ($pair:expr, $bits:literal, $g:ident, $m:ident, $k:literal, $s:literal) => {{
        let (mut a, mut b, mut c, mut d) = ([0; $s], [0; $s], [0; $s], [0; $s]);
        let gkey = [0x19; $k];
        let mkey = [0x53; $k];
        let mut gs =
            g::execution::$g::<16>::from_reserved_range($pair, &gkey, &mut a, *b"gcm!", 0, 100_000)
                .unwrap();
        let mut ms =
            m::execution::$m::<16>::from_reserved_range($pair, &mkey, &mut b, *b"mac!", 0, 100_000)
                .unwrap();
        let mut gp = g::$g::<16>::from_reserved_range(&gkey, &mut c, *b"gcm!", 0, 2).unwrap();
        let mut mp = m::$m::<16>::from_reserved_range(&mkey, &mut d, *b"mac!", 0, 2).unwrap();
        let (mut ct, mut expected, mut scratch) = ([0; N], [0; N], [0; N]);
        let mut gt = ([0; 12], [0; 16]);
        let mut mt = ([0; 12], [0; 16]);
        let aad = [0x31; N];
        for byte in [0, 255] {
            let input = [byte; N];
            gt = gp
                .seal_next(&aad, &input, &mut expected, &mut scratch)
                .unwrap();
            assert_eq!(
                gs.seal_next(&aad, &input, &mut ct, &mut scratch).unwrap(),
                gt
            );
            assert_eq!(ct, expected);
            gs.open(&gt.0, &aad, &gt.1, &ct, &mut expected, &mut scratch)
                .unwrap();
            assert_eq!(expected, input);
            let (iv, tag) = mp.authenticate_next(&input).unwrap();
            let (ni, nt) = ms.authenticate_next(&input).unwrap();
            assert_eq!((ni, nt.as_bytes()), (iv, tag.as_bytes()));
            ms.verify(&iv, &input, &tag).unwrap();
            mt = (iv, *tag.as_bytes());
        }
        let mut buf = [0; N];
        let mut tag = [0; 16];
        for op in ["seal", "open-reject", "generate", "verify-reject"] {
            for (control, identical) in [("identical", true), ("values", false)] {
                let name = format!("{}-{op}-{control}", $bits);
                campaign(&name, |class| {
                    let other = black_box(class && !identical);
                    match op {
                        "seal" => {
                            buf.fill(if other { 255 } else { 0 });
                            let input = black_box(&buf);
                            let t = Instant::now();
                            for _ in 0..REPS {
                                black_box(
                                    gs.seal_next(&aad, input, &mut expected, &mut scratch)
                                        .unwrap(),
                                );
                            }
                            t.elapsed().as_nanos()
                        }
                        "generate" => {
                            buf.fill(if other { 255 } else { 0 });
                            let input = black_box(&buf);
                            let t = Instant::now();
                            for _ in 0..REPS {
                                black_box(ms.authenticate_next(input).unwrap());
                            }
                            t.elapsed().as_nanos()
                        }
                        "open-reject" => {
                            tag = gt.1;
                            tag[if other { 15 } else { 0 }] ^= 1;
                            let input = black_box(&tag);
                            let t = Instant::now();
                            for _ in 0..REPS {
                                assert_eq!(
                                    gs.open(&gt.0, &aad, input, &ct, &mut expected, &mut scratch),
                                    Err(g::GcmError::Authentication)
                                );
                            }
                            t.elapsed().as_nanos()
                        }
                        "verify-reject" => {
                            tag = mt.1;
                            tag[if other { 15 } else { 0 }] ^= 1;
                            let proposed = m::GmacTag::from_bytes(tag);
                            let input = black_box(&proposed);
                            let t = Instant::now();
                            for _ in 0..REPS {
                                assert_eq!(
                                    ms.verify(&mt.0, &[255; N], input),
                                    Err(m::GmacError::Authentication)
                                );
                            }
                            t.elapsed().as_nanos()
                        }
                        _ => unreachable!(),
                    }
                });
            }
        }
    }};
}

fn main() {
    let pair = g::execution::X86AesPair::require().unwrap();
    width!(&pair, 128, Aes128Gcm, Aes128Gmac, 16, 176);
    width!(&pair, 192, Aes192Gcm, Aes192Gmac, 24, 208);
    width!(&pair, 256, Aes256Gcm, Aes256Gmac, 32, 240);
    campaign("sensitivity", |class| {
        let t = Instant::now();
        let mut x = black_box(1u32);
        if class {
            for _ in 0..256 {
                x = black_box(x.wrapping_mul(3).wrapping_add(1));
            }
        }
        black_box(x);
        t.elapsed().as_nanos()
    });
}
