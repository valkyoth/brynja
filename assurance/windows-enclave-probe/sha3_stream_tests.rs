use super::*;
use std::{vec, vec::Vec};

// Miri targets ownership/clearing here, not repeated Keccak permutations. The
// complete real-crypto lifecycle and oracle campaigns run separately above it.
#[test]
fn focused_memory_lifecycle() {
    for unwind in [false, true] {
        let mut owner = Owner::new();
        owner.phase = Phase::RetainedFinal;
        owner.algorithm = Some(Algorithm::Sha3_256);
        owner.output.fill(0xa5);
        owner.width = 32;
        owner.last = 8;
        if unwind {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    owner.export_public(1, 2, 32, 8, |_| panic!("copy failure"))
                }))
                .is_err()
            );
        } else {
            assert_eq!(
                owner.export_public(1, 2, 32, 8, |_| false),
                Err(Error::Copy)
            );
        }
        quarantined(&owner);
    }
    for phase in [
        Phase::Streaming,
        Phase::Squeezing,
        Phase::RetainedMore,
        Phase::RetainedFinal,
    ] {
        let mut owner = Owner::new();
        owner.phase = phase;
        owner.output.fill(0xa5);
        owner.cancel(1).unwrap();
        clean(&owner);
        assert_eq!(owner.phase, Phase::Empty);
    }
    let mut owner = Owner::new();
    owner.phase = Phase::RetainedFinal;
    owner.sequence = u64::MAX;
    owner.output.fill(0xa5);
    assert_eq!(owner.cancel(0), Err(Error::Sequence));
    quarantined(&owner);
}
fn empty() -> Fips202BitString<'static> {
    Fips202BitString::new(&[], 0).unwrap()
}
fn valid(bits: usize) -> u8 {
    if bits == 0 {
        0
    } else {
        ((bits - 1) % 8 + 1) as u8
    }
}
fn hex(text: &str) -> Vec<u8> {
    if text == "-" {
        return vec![];
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn clean(owner: &Owner) {
    assert!(owner.output.iter().all(|b| *b == 0));
    assert!(matches!(owner.state, State::Empty));
    assert!(owner.algorithm.is_none());
    assert_eq!((owner.width, owner.last), (0, 0));
}
fn quarantined(owner: &Owner) {
    assert_eq!(owner.phase, Phase::Quarantined);
    clean(owner);
}
fn check_case(
    id: u64,
    n: Fips202BitString<'_>,
    s: Fips202BitString<'_>,
    input: &[u8],
    last: u8,
    expected: &[u8],
    out_last: u8,
) {
    for partition in [1, 17, 1024] {
        let mut owner = Owner::new();
        let mut seq = 1;
        owner.begin(seq, id, n, s).unwrap();
        let whole = if last == 8 {
            input.len()
        } else {
            input.len().saturating_sub(1)
        };
        for chunk in input[..whole].chunks(partition) {
            seq += 1;
            owner.update(seq, chunk).unwrap();
        }
        seq += 1;
        owner
            .finish(
                seq,
                &input[whole..],
                if whole == input.len() { 0 } else { last },
            )
            .unwrap();
        if id <= 4 {
            seq += 1;
            owner
                .export_public(seq, id, expected.len(), out_last, |bytes| {
                    assert_eq!(bytes, expected);
                    true
                })
                .unwrap();
        } else {
            let whole = if out_last == 8 {
                expected.len()
            } else {
                expected.len().saturating_sub(1)
            };
            for chunk in expected[..whole].chunks(partition) {
                seq += 1;
                owner.squeeze(seq, chunk.len(), 8, false).unwrap();
                seq += 1;
                owner
                    .export_public(seq, id, chunk.len(), 8, |bytes| {
                        assert_eq!(bytes, chunk);
                        true
                    })
                    .unwrap();
                assert!(owner.output.iter().all(|b| *b == 0));
            }
            let tail = &expected[whole..];
            let last = if tail.is_empty() { 0 } else { out_last };
            seq += 1;
            owner.squeeze(seq, tail.len(), last, true).unwrap();
            seq += 1;
            owner
                .export_public(seq, id, tail.len(), last, |bytes| {
                    assert_eq!(bytes, tail);
                    true
                })
                .unwrap();
        }
        assert_eq!(owner.phase, Phase::Empty);
        clean(&owner);
    }
}
#[test]
fn official_bits_and_cshake_oracles() {
    let mut count = 0;
    for line in include_str!("cshake-execution.txt")
        .lines()
        .filter(|s| !s.starts_with('#') && !s.is_empty())
    {
        let f: Vec<_> = line.split_whitespace().collect();
        assert_eq!(f.len(), 9);
        let n = hex(f[2]);
        let s = hex(f[4]);
        let x = hex(f[6]);
        let y = hex(f[8]);
        let lengths: Vec<usize> = [1, 3, 5, 7].map(|i| f[i].parse().unwrap()).to_vec();
        check_case(
            if f[0] == "cshake128" {
                7
            } else {
                assert_eq!(f[0], "cshake256");
                8
            },
            Fips202BitString::new(&n, valid(lengths[0])).unwrap(),
            Fips202BitString::new(&s, valid(lengths[1])).unwrap(),
            &x,
            valid(lengths[2]),
            &y,
            valid(lengths[3]),
        );
        count += 1;
    }
    assert_eq!(count, 628);
    let mut count = 0;
    for line in include_str!("nist-bit-selected.txt")
        .lines()
        .filter(|s| !s.starts_with('#') && !s.is_empty())
    {
        let f: Vec<_> = line.split_whitespace().collect();
        assert_eq!(f.len(), 5);
        let id = match f[0] {
            "sha3-224" => 1,
            "sha3-256" => 2,
            "sha3-384" => 3,
            "sha3-512" => 4,
            "shake128" => 5,
            "shake256" => 6,
            _ => panic!("identity"),
        };
        let bits: usize = f[1].parse().unwrap();
        let output: usize = f[2].parse().unwrap();
        let x = if bits == 0 { vec![] } else { hex(f[3]) };
        check_case(
            id,
            empty(),
            empty(),
            &x,
            valid(bits),
            &hex(f[4]),
            valid(output),
        );
        count += 1;
    }
    assert_eq!(count, 76);
}
#[test]
fn exact_retained_bit_composition_all_pairs() {
    use brynja_hash_sha3::{
        Fips202Output, cshake128_bits, cshake256_bits, sha3_224_bits, sha3_256_bits, sha3_384_bits,
        sha3_512_bits,
    };
    for source in 1..=8 {
        for target in 1..=8 {
            for tail in 1..=8 {
                let mut owner = Owner::new();
                owner.begin(1, source, empty(), empty()).unwrap();
                owner.finish(2, b"abc", 8).unwrap();
                let seq = if source > 4 {
                    owner.squeeze(3, 37, tail, true).unwrap();
                    4
                } else {
                    3
                };
                let input = owner.output[..owner.width].to_vec();
                let bits = Fips202BitString::new(&input, owner.last).unwrap();
                let mut expected = vec![
                    0;
                    Algorithm::decode(target)
                        .unwrap()
                        .fixed_width()
                        .unwrap_or(65)
                ];
                match target {
                    1 => expected.copy_from_slice(sha3_224_bits(bits).unwrap().as_bytes()),
                    2 => expected.copy_from_slice(sha3_256_bits(bits).unwrap().as_bytes()),
                    3 => expected.copy_from_slice(sha3_384_bits(bits).unwrap().as_bytes()),
                    4 => expected.copy_from_slice(sha3_512_bits(bits).unwrap().as_bytes()),
                    5 | 7 => cshake128_bits(
                        bits,
                        empty(),
                        empty(),
                        Fips202Output::new(&mut expected, 8).unwrap(),
                    )
                    .unwrap(),
                    6 | 8 => cshake256_bits(
                        bits,
                        empty(),
                        empty(),
                        Fips202Output::new(&mut expected, 8).unwrap(),
                    )
                    .unwrap(),
                    _ => unreachable!(),
                }
                owner.rehash(seq, target, empty(), empty()).unwrap();
                let seq = if target > 4 {
                    owner.squeeze(seq + 1, expected.len(), 8, true).unwrap();
                    seq + 2
                } else {
                    seq + 1
                };
                owner
                    .export_public(seq, target, expected.len(), 8, |b| {
                        assert_eq!(b, expected);
                        true
                    })
                    .unwrap();
                clean(&owner);
            }
        }
    }
}
#[test]
fn lifecycle_sequence_shape_and_failed_copy() {
    for id in 1..=8 {
        let mut owner = Owner::new();
        owner.begin(1, id, empty(), empty()).unwrap();
        owner.cancel(2).unwrap();
        clean(&owner);
        owner.begin(3, id, empty(), empty()).unwrap();
        assert_eq!(owner.update(3, b"x"), Err(Error::Sequence));
        quarantined(&owner);
        let mut owner = Owner::new();
        owner.sequence = u64::MAX;
        assert_eq!(owner.begin(0, id, empty(), empty()), Err(Error::Sequence));
        quarantined(&owner);
        let mut owner = Owner::new();
        owner.begin(1, id, empty(), empty()).unwrap();
        assert_eq!(owner.update(2, &[0; 1025]), Err(Error::Length));
        quarantined(&owner);
        let mut owner = Owner::new();
        owner.begin(1, id, empty(), empty()).unwrap();
        assert_eq!(owner.finish(2, &[0x80], 1), Err(Error::Bits));
        quarantined(&owner);
        for failure in 0..4 {
            let mut owner = Owner::new();
            owner.begin(1, id, empty(), empty()).unwrap();
            owner.finish(2, b"abc", 8).unwrap();
            let seq = if id > 4 {
                owner.squeeze(3, 32, 8, true).unwrap();
                4
            } else {
                3
            };
            let width = owner.width;
            let result = match failure {
                0 => owner.export_public(seq, id, width, 8, |_| false),
                1 => owner.export_public(seq, id + 1, width, 8, |_| panic!("identity bypass")),
                2 => owner.export_public(seq, id, width + 1, 8, |_| panic!("shape bypass")),
                _ => {
                    assert!(
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                            || owner.export_public(seq, id, width, 8, |_| panic!("copy unwind"))
                        ))
                        .is_err()
                    );
                    Err(Error::Copy)
                }
            };
            assert!(result.is_err());
            quarantined(&owner);
        }
    }
    for phase in [
        Phase::Empty,
        Phase::Streaming,
        Phase::Squeezing,
        Phase::RetainedMore,
        Phase::RetainedFinal,
        Phase::Quarantined,
    ] {
        let mut owner = Owner::new();
        owner.phase = phase;
        if phase != Phase::Streaming {
            assert_eq!(owner.update(1, b"x"), Err(Error::State));
            quarantined(&owner);
        }
    }
}
#[test]
fn xof_terminal_bounds_and_identity() {
    for id in 5..=8 {
        for terminal in [false, true] {
            let mut owner = Owner::new();
            owner.begin(1, id, empty(), empty()).unwrap();
            owner.finish(2, &[], 0).unwrap();
            assert_eq!(owner.squeeze(3, 1025, 8, terminal), Err(Error::Length));
            quarantined(&owner);
            let mut owner = Owner::new();
            owner.begin(1, id, empty(), empty()).unwrap();
            owner.finish(2, &[], 0).unwrap();
            owner.squeeze(3, 1024, 8, terminal).unwrap();
            assert_eq!(owner.squeeze(4, 1, 8, false), Err(Error::State));
            quarantined(&owner);
        }
    }
    let mut owner = Owner::new();
    owner.begin(1, 5, empty(), empty()).unwrap();
    owner.finish(2, &[], 0).unwrap();
    assert_eq!(owner.squeeze(3, 1, 7, false), Err(Error::Bits));
    quarantined(&owner);
    for id in [0, 9, u64::MAX] {
        let mut owner = Owner::new();
        assert_eq!(owner.begin(1, id, empty(), empty()), Err(Error::Identity));
        quarantined(&owner);
    }
    for id in 1..=6 {
        let mut owner = Owner::new();
        assert_eq!(
            owner.begin(1, id, Fips202BitString::new(b"x", 8).unwrap(), empty()),
            Err(Error::Identity)
        );
        quarantined(&owner);
    }
    let mut owner = Owner::new();
    assert_eq!(
        owner.begin(1, 7, Fips202BitString::new(&[0; 1025], 8).unwrap(), empty()),
        Err(Error::Length)
    );
    quarantined(&owner);
    // This worker is intended for one existing 4096-byte retained allocation.
    assert!(core::mem::size_of::<Owner>() <= 4096);
}
