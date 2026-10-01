use super::*;
use std::vec;

fn authority() -> Authority {
    Authority::new(Kernel::X86Keccak).unwrap()
}
fn empty() -> Fips202BitString<'static> {
    Fips202BitString::new(&[], 0).unwrap()
}
fn failed(owner: &Owner<'_>) {
    assert_eq!(owner.phase, Phase::Quarantined);
    assert!(owner.output.iter().all(|b| *b == 0));
    assert!(matches!(owner.state, State::Empty));
    assert!(owner.authority.session().is_err());
}

#[test]
fn exact_authority_and_revocation_cover_non_permuting_operations() {
    // Wrong identity is rejected even before trying to establish its session.
    if let Ok(wrong) = Authority::new(Kernel::X86Sha256) {
        assert!(matches!(Owner::new(&wrong), Err(Error::Backend)));
    }
    for point in 0..8 {
        let authority = authority();
        let mut owner = Owner::new(&authority).unwrap();
        match point {
            0 => {}
            1 | 2 => owner.begin(1, 2, empty(), empty()).unwrap(),
            3 | 4 => {
                owner.begin(1, 2, empty(), empty()).unwrap();
                owner.finish(2, b"abc", 8).unwrap();
            }
            5 => {
                owner.begin(1, 5, empty(), empty()).unwrap();
                owner.finish(2, &[], 0).unwrap();
            }
            _ => owner.setup(1, 7, 1, 1).unwrap(),
        }
        authority.quarantine();
        let result = match point {
            0 => owner.begin(1, 2, empty(), empty()),
            1 => owner.update(2, &[]),
            2 => owner.cancel(2),
            3 => owner.export_public(3, 2, 32, 8, |_| panic!("revoked export")),
            4 => owner.rehash(3, 3, empty(), empty()),
            5 => owner.squeeze(3, 0, 0, true),
            6 => owner.setup_chunk(2, true, &[], 0),
            _ => owner.finish_setup(2),
        };
        assert_eq!(result, Err(Error::Backend));
        failed(&owner);
        assert!(matches!(Owner::new(&authority), Err(Error::Backend)));
    }
}

#[test]
fn copy_failure_unwind_and_revocation_during_copy_clear_and_latch() {
    for mode in 0..3 {
        let authority = authority();
        let mut owner = Owner::new(&authority).unwrap();
        owner.begin(1, 2, empty(), empty()).unwrap();
        owner.finish(2, b"secret fixture", 8).unwrap();
        if mode == 0 {
            assert_eq!(
                owner.export_public(3, 2, 32, 8, |_| false),
                Err(Error::Copy)
            );
        } else if mode == 1 {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    owner.export_public(3, 2, 32, 8, |_| panic!("injected copy unwind"))
                }))
                .is_err()
            );
        } else {
            assert_eq!(
                owner.export_public(3, 2, 32, 8, |_| {
                    authority.quarantine();
                    true
                }),
                Err(Error::Backend)
            );
        }
        failed(&owner);
    }
}

#[test]
fn fractional_customization_fragments_preserve_exact_bits() {
    let n = [0x5b, 0x69];
    let s = [0xe3, 0x37];
    for id in [7, 8] {
        for nb in 0..=16_usize {
            for sb in 0..=16_usize {
                let canonical = |bytes: &[u8; 2], count: usize| {
                    let mut out = bytes[..count.div_ceil(8)].to_vec();
                    if count % 8 != 0 {
                        *out.last_mut().unwrap() &= 0xff >> (8 - count % 8);
                    }
                    out
                };
                let name = canonical(&n, nb);
                let custom = canonical(&s, sb);
                let last = |bits: usize| {
                    if bits == 0 {
                        0
                    } else {
                        ((bits - 1) % 8 + 1) as u8
                    }
                };
                let mut expected = [0; 37];
                macro_rules! oracle {
                    ($function:ident) => {
                        brynja_hash_sha3::$function(
                            Fips202BitString::new(b"m", 8).unwrap(),
                            Fips202BitString::new(&name, last(nb)).unwrap(),
                            Fips202BitString::new(&custom, last(sb)).unwrap(),
                            brynja_hash_sha3::Fips202Output::new(&mut expected, 3).unwrap(),
                        )
                        .unwrap()
                    };
                }
                if id == 7 {
                    oracle!(cshake128_bits);
                } else {
                    oracle!(cshake256_bits);
                }
                let authority = authority();
                let mut owner = Owner::new(&authority).unwrap();
                owner.setup(1, id, nb as u128, sb as u128).unwrap();
                let mut seq = 1;
                for (is_name, bytes, bits) in [(true, &n, nb), (false, &s, sb)] {
                    for i in 0..bits {
                        let bit = [(bytes[i / 8] >> (i % 8)) & 1];
                        seq += 1;
                        owner.setup_chunk(seq, is_name, &bit, 1).unwrap();
                    }
                }
                seq += 1;
                owner.finish_setup(seq).unwrap();
                seq += 1;
                owner.finish(seq, b"m", 8).unwrap();
                seq += 1;
                owner.squeeze(seq, 37, 3, true).unwrap();
                seq += 1;
                owner
                    .export_public(seq, id, 37, 3, |out| {
                        assert_eq!(out, expected);
                        true
                    })
                    .unwrap();
            }
        }
    }
}

#[test]
fn prefix_overflow_incomplete_and_excess_are_terminal() {
    for id in [7, 8] {
        for (name, custom) in [(u128::MAX, 0), (0, u128::MAX), (u128::MAX, u128::MAX)] {
            let authority = authority();
            let mut owner = Owner::new(&authority).unwrap();
            assert!(owner.setup(1, id, name, custom).is_err());
            failed(&owner);
        }
        for mode in 0..3 {
            let authority = authority();
            let mut owner = Owner::new(&authority).unwrap();
            owner.setup(1, id, 1, 1).unwrap();
            let result = match mode {
                0 => owner.setup_chunk(2, true, &[0], 2),
                1 => owner.setup_chunk(2, false, &[0], 1),
                _ => owner.finish_setup(2),
            };
            assert!(result.is_err());
            failed(&owner);
        }
    }
    // Neither the component nor its retained result allocates from input lengths.
    assert!(core::mem::size_of::<Owner<'_>>() <= 4096);
    let authority = authority();
    let mut owner = Owner::new(&authority).unwrap();
    owner.setup(1, 7, 0, 0).unwrap();
    owner.finish_setup(2).unwrap();
    owner.update(3, &vec![7; 1024]).unwrap();
    owner.cancel(4).unwrap();
    assert!(authority.session().is_ok());
}
