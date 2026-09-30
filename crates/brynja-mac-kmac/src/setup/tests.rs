use super::*;
extern crate std;
use std::{boxed::Box, vec, vec::Vec};

fn must<T, E: Send + 'static>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error)))
}
fn bits(bytes: &[u8], count: usize) -> Fips202BitString<'_> {
    must(Fips202BitString::new(
        bytes,
        if count == 0 {
            0
        } else {
            must(u8::try_from(
                (count.saturating_sub(1) % 8).saturating_add(1),
            ))
        },
    ))
}
fn fragment(input: &[u8], start: usize, count: usize) -> Vec<u8> {
    let mut output = vec![0; count.div_ceil(8)];
    for i in 0..count {
        let at = start.saturating_add(i);
        let source = input
            .get(at / 8)
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new(())));
        let byte = output
            .get_mut(i / 8)
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new(())));
        *byte |= ((source >> (at % 8)) & 1) << (i % 8);
    }
    output
}

#[test]
fn streamed_setup_matches_all_four_contiguous_identities() {
    for (kb, sb) in [(256, 0), (257, 1), (271, 9), (1089, 1345), (8193, 8201)] {
        let key = fragment(&[0xa5; 1100], 0, kb);
        let custom = fragment(&[0x96; 1100], 0, sb);
        for chunk in [1, 7, 8, 17, 1024] {
            macro_rules! check {
                ($setup:ident,$fixed:ident,$xof:ident) => {{
                    let prepare = || {
                        let mut setup = must($setup::new(kb as u128, sb as u128));
                        for start in (0..sb).step_by(chunk) {
                            let count = chunk.min(sb.saturating_sub(start));
                            must(
                                setup.customization(bits(&fragment(&custom, start, count), count)),
                            );
                        }
                        must(setup.finish_customization());
                        for start in (0..kb).step_by(chunk) {
                            let count = chunk.min(kb.saturating_sub(start));
                            must(setup.key(bits(&fragment(&key, start, count), count)));
                        }
                        setup
                    };
                    let mut actual = [0; 65];
                    let mut expected = [0; 65];
                    let tag = must(must(prepare().finish()).finalize_tag_bits(
                        bits(&[3], 2),
                        &mut actual,
                        3,
                    ));
                    let reference = must(
                        must($fixed::new_bits(bits(&key, kb), bits(&custom, sb)))
                            .finalize_tag_bits(bits(&[3], 2), &mut expected, 3),
                    );
                    assert_eq!(tag.as_bytes(), reference.as_bytes());
                    let mut actual = [0; 201];
                    let mut expected = [0; 201];
                    let reader =
                        must(must(prepare().finish_xof()).finalize_bits_xof(bits(&[3], 2)));
                    let reference = must(
                        must($xof::new_bits(bits(&key, kb), bits(&custom, sb)))
                            .finalize_bits_xof(bits(&[3], 2)),
                    );
                    let proof = crate::KmacPublicDeclassification::acknowledge();
                    must(reader.squeeze_final_bits_public(
                        must(crate::Fips202Output::new(&mut actual, 3)),
                        proof,
                    ));
                    must(reference.squeeze_final_bits_public(
                        must(crate::Fips202Output::new(&mut expected, 3)),
                        crate::KmacPublicDeclassification::acknowledge(),
                    ));
                    assert_eq!(actual, expected);
                }};
            }
            check!(Kmac128Setup, Kmac128, KmacXof128);
            check!(Kmac256Setup, Kmac256, KmacXof256);
        }
    }
}
