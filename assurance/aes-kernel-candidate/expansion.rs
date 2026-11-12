//! Candidate schedule tests. Reference expansion is test-only and independent.
use super::{available, expand, transform, vectors};

#[cfg(target_arch = "x86_64")]
#[path = "../../crates/brynja-crypto-cpu/src/aes/x86_expand.rs"]
mod candidate;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[path = "../../crates/brynja-crypto-cpu/src/aes/aarch64_expand.rs"]
mod candidate;

fn expand_candidate<const K: usize, const S: usize>(key: &[u8; K], output: &mut [u8; S]) {
    assert!(available(), "expansion ISA unavailable; no skipped pass");
    // SAFETY: Runtime bundle checks above and stable test-host ISA are required.
    // Exact disjoint byte arrays bound all accesses; only public fixtures used.
    unsafe { candidate::expand(key, output) };
}

macro_rules! corpus {
    ($test:ident, $bits:literal, $k:literal, $s:literal, $n:literal, $gfs:literal, $sbox:literal, $total:literal) => {
        #[test]
        fn $test() {
            let mut total = 0;
            for (text, count) in [
                (
                    include_str!(concat!(
                        "../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBGFSbox",
                        $bits,
                        ".rsp"
                    )),
                    $gfs,
                ),
                (
                    include_str!(concat!(
                        "../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBKeySbox",
                        $bits,
                        ".rsp"
                    )),
                    $sbox,
                ),
                (
                    include_str!(concat!(
                        "../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBVarKey",
                        $bits,
                        ".rsp"
                    )),
                    $bits,
                ),
                (
                    include_str!(concat!(
                        "../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBVarTxt",
                        $bits,
                        ".rsp"
                    )),
                    128,
                ),
            ] {
                for vector in vectors::<$k>(text, count).unwrap() {
                    let before = vector.key;
                    let reference = expand::<$n>(&vector.key);
                    let mut schedule = [0xa5; $s];
                    expand_candidate(&vector.key, &mut schedule);
                    assert_eq!(vector.key, before);
                    assert_eq!(
                        schedule.as_slice(),
                        reference.as_flattened(),
                        "complete schedule differs at record {total}"
                    );
                    let generated = schedule;
                    let keys: &[[u8; 16]; $n] = schedule.as_chunks::<16>().0.try_into().unwrap();
                    let mut block = vector.input;
                    transform(&mut block, keys, vector.inverse);
                    assert_eq!(block, vector.expected, "NIST answer record {total}");
                    transform(&mut block, keys, !vector.inverse);
                    assert_eq!(block, vector.input);
                    assert_eq!(schedule, generated, "round kernel changed schedule");
                    total += 1;
                }
            }
            assert_eq!(total, $total);
            println!("\nAES_EXPANSION_KAT_PASS: {}:{}", $bits, total);
        }
    };
}
corpus!(aes128_schedule_and_vectors, 128, 16, 176, 11, 7, 21, 568);
corpus!(aes192_schedule_and_vectors, 192, 24, 208, 13, 6, 24, 700);
corpus!(aes256_schedule_and_vectors, 256, 32, 240, 15, 5, 16, 810);

fn alignment<const K: usize, const S: usize, const N: usize>() {
    let key: [u8; K] = std::array::from_fn(|i| i as u8);
    let reference = expand::<N>(&key);
    for key_offset in 0..16 {
        for schedule_offset in 0..16 {
            let mut keys = vec![0xa5; K + 32];
            keys[key_offset..key_offset + K].copy_from_slice(&key);
            let before = keys.clone();
            let input: &[u8; K] = keys[key_offset..key_offset + K].try_into().unwrap();
            let mut output = vec![0x5a; S + 32];
            let schedule: &mut [u8; S] = (&mut output[schedule_offset..schedule_offset + S])
                .try_into()
                .unwrap();
            expand_candidate(input, schedule);
            assert_eq!(schedule.as_slice(), reference.as_flattened());
            assert_eq!(keys, before, "input/canaries changed");
            assert!(output[..schedule_offset].iter().all(|b| *b == 0x5a));
            assert!(output[schedule_offset + S..].iter().all(|b| *b == 0x5a));
        }
    }
}

#[test]
fn every_key_and_schedule_byte_alignment() {
    alignment::<16, 176, 11>();
    alignment::<24, 208, 13>();
    alignment::<32, 240, 15>();
    println!("\nAES_EXPANSION_ALIGNMENT_PASS: 768");
}

fn generated<const K: usize, const S: usize, const N: usize>() {
    for value in 0..=255u8 {
        // Every byte value at every input position, with varied neighboring bytes.
        let key: [u8; K] = std::array::from_fn(|i| value.wrapping_add((i as u8).wrapping_mul(73)));
        let mut schedule = [0; S];
        expand_candidate(&key, &mut schedule);
        assert_eq!(schedule.as_slice(), expand::<N>(&key).as_flattened());
    }
    for key in [[0; K], [255; K]] {
        let mut schedule = [0; S];
        expand_candidate(&key, &mut schedule);
        assert_eq!(schedule.as_slice(), expand::<N>(&key).as_flattened());
    }
}

#[test]
fn generated_keys_match_every_schedule_byte() {
    generated::<16, 176, 11>();
    generated::<24, 208, 13>();
    generated::<32, 240, 15>();
    println!("\nAES_EXPANSION_GENERATED_PASS: 774");
}
