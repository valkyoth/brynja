use super::*;
use crate::{Fips202Output, cshake128_bits, cshake256_bits};
extern crate std;
use std::{vec, vec::Vec};

fn bits(bytes: &[u8], len: usize) -> Fips202BitString<'_> {
    Fips202BitString::new(
        bytes,
        if len == 0 {
            0
        } else {
            u8::try_from((len.saturating_sub(1) % 8).saturating_add(1))
                .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)))
        },
    )
    .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)))
}
fn fragment(input: &[u8], start: usize, count: usize) -> Vec<u8> {
    let mut out = vec![0; count.div_ceil(8)];
    for i in 0..count {
        let at = start
            .checked_add(i)
            .unwrap_or_else(|| std::panic::resume_unwind(std::boxed::Box::new(())));
        let source = input
            .get(at / 8)
            .unwrap_or_else(|| std::panic::resume_unwind(std::boxed::Box::new(())));
        let destination = out
            .get_mut(i / 8)
            .unwrap_or_else(|| std::panic::resume_unwind(std::boxed::Box::new(())));
        *destination |= ((source >> (at % 8)) & 1) << (i % 8);
    }
    out
}
#[test]
fn fragmented_domains_match_contiguous_at_all_bit_offsets() {
    for (nb, sb) in [
        (0, 0),
        (0, 7),
        (1, 0),
        (1, 1),
        (7, 9),
        (8, 8),
        (9, 15),
        (1087, 1089),
        (1343, 1345),
        (8193, 8201),
    ] {
        let name = fragment(&[0xa5; 1100], 0, nb);
        let custom = fragment(&[0x96; 1100], 0, sb);
        for chunk in [1, 7, 8, 17, 1024] {
            macro_rules! check {
                ($setup:ident,$reference:ident) => {{
                    let mut setup = $setup::new(nb as u128, sb as u128).unwrap_or_else(|error| {
                        std::panic::resume_unwind(std::boxed::Box::new(error))
                    });
                    for start in (0..nb).step_by(chunk) {
                        let count = chunk.min(nb - start);
                        let input = fragment(&name, start, count);
                        setup.name(bits(&input, count)).unwrap_or_else(|error| {
                            std::panic::resume_unwind(std::boxed::Box::new(error))
                        });
                    }
                    for start in (0..sb).step_by(chunk) {
                        let count = chunk.min(sb - start);
                        let input = fragment(&custom, start, count);
                        setup
                            .customization(bits(&input, count))
                            .unwrap_or_else(|error| {
                                std::panic::resume_unwind(std::boxed::Box::new(error))
                            });
                    }
                    let state = setup.finish().unwrap_or_else(|error| {
                        std::panic::resume_unwind(std::boxed::Box::new(error))
                    });
                    let mut reader =
                        state
                            .finalize_bits_xof(bits(&[0x13], 5))
                            .unwrap_or_else(|error| {
                                std::panic::resume_unwind(std::boxed::Box::new(error))
                            });
                    let mut actual = [0; 201];
                    let mut expected = [0; 201];
                    $reference(
                        bits(&[0x13], 5),
                        bits(&name, nb),
                        bits(&custom, sb),
                        Fips202Output::new(&mut expected, 3).unwrap_or_else(|error| {
                            std::panic::resume_unwind(std::boxed::Box::new(error))
                        }),
                    )
                    .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)));
                    let out = reader
                        .squeeze_final_bits_secret_erasing_source(
                            Fips202Output::new(&mut actual, 3).unwrap_or_else(|error| {
                                std::panic::resume_unwind(std::boxed::Box::new(error))
                            }),
                        )
                        .unwrap_or_else(|error| {
                            std::panic::resume_unwind(std::boxed::Box::new(error))
                        });
                    assert_eq!(out.expose(), expected);
                    drop(out);
                    assert_eq!(actual, [0; 201]);
                }};
            }
            check!(HardenedCshake128Setup, cshake128_bits);
            check!(HardenedCshake256Setup, cshake256_bits);
        }
    }
}
fn cleared<const R: usize>(setup: &Setup<R>) {
    assert!(setup.owner.is_none());
    assert_eq!(setup.pending, [0]);
    assert_eq!(setup.used, 0);
    assert!(setup.phase == Phase::Dead);
}
#[test]
fn in_place_completion_erases_source_on_success_and_error() {
    for complete in [false, true] {
        let mut setup = Setup::<168>::new(1, 0)
            .unwrap_or_else(|e| std::panic::resume_unwind(std::boxed::Box::new(e)));
        if complete {
            setup
                .push(Phase::Name, bits(&[1], 1))
                .unwrap_or_else(|e| std::panic::resume_unwind(std::boxed::Box::new(e)));
        }
        assert_eq!(setup.finish_erasing_source().is_ok(), complete);
        cleared(&setup);
        assert!(setup.finish_erasing_source().is_err());
        cleared(&setup);
    }
}
#[test]
fn errors_and_unwind_clear_and_cannot_reopen_setup() {
    let mut setup = Setup::<136>::new(3, 9)
        .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)));
    assert!(setup.push(Phase::Custom, bits(&[1], 1)).is_err());
    cleared(&setup);
    assert!(setup.push(Phase::Name, bits(&[1], 1)).is_err());
    cleared(&setup);
    let mut setup = Setup::<136>::new(3, 9)
        .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)));
    setup
        .push(Phase::Name, bits(&[1], 1))
        .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)));
    assert_ne!(setup.pending, [0]);
    assert!(setup.push(Phase::Name, bits(&[7], 3)).is_err());
    cleared(&setup);
    let mut setup = Setup::<136>::new(3, 9)
        .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)));
    setup
        .push(Phase::Name, bits(&[1], 1))
        .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = Operation {
                setup: &mut setup,
                complete: false,
            };
            std::panic::resume_unwind(std::boxed::Box::new(()));
        }))
        .is_err()
    );
    cleared(&setup);
    assert!(
        Setup::<136>::new(1, 0)
            .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)))
            .finish()
            .is_err()
    );
    assert!(
        Setup::<136>::new(0, 1)
            .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)))
            .finish()
            .is_err()
    );
    assert!(Setup::<136>::new(u128::MAX, 0).is_err());
    assert!(Setup::<136>::new(0, u128::MAX).is_err());
    assert!(Setup::<136>::new(u128::MAX, u128::MAX).is_err());
    assert!(Setup::<0>::new(0, 0).is_err());
}
#[test]
fn completion_checks_shape_not_just_phase() {
    for corruption in 0..4 {
        let mut setup = Setup::<168>::new(0, 0)
            .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)));
        match corruption {
            0 => setup.remaining = 1,
            1 => setup.used = 1,
            2 => setup.emitted = 1,
            _ => setup.expected = 1,
        }
        assert!(setup.finish().is_err());
    }
    let mut setup = Setup::<168>::new(1, 0)
        .unwrap_or_else(|error| std::panic::resume_unwind(std::boxed::Box::new(error)));
    setup.expected += 1;
    assert!(setup.push(Phase::Name, bits(&[1], 1)).is_err());
    cleared(&setup);
}
