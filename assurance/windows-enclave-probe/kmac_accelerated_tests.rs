use super::*;
use std::vec;
pub(super) fn whole(bytes: &[u8]) -> Fips202BitString<'_> {
    Fips202BitString::new(bytes, if bytes.is_empty() { 0 } else { 8 }).unwrap()
}
pub(super) fn empty() -> Fips202BitString<'static> {
    whole(&[])
}
pub(super) fn bits(bytes: &[u8], last: u8) -> Fips202BitString<'_> {
    Fips202BitString::new(bytes, last).unwrap()
}
pub(super) fn authority() -> Authority {
    Authority::new(Kernel::X86Keccak).unwrap()
}
pub(super) fn feed(owner: &mut Owner<'_>, seq: &mut u64, input: Fips202BitString<'_>, key: bool) {
    let complete = input.bit_len() / 8;
    for chunk in input.as_bytes()[..complete].chunks(37) {
        *seq += 1;
        if key {
            owner.key(*seq, whole(chunk))
        } else {
            owner.customization(*seq, whole(chunk))
        }
        .unwrap();
    }
    let last = input.valid_bits_in_last_byte();
    if (1..8).contains(&last) {
        // Split even the last fractional byte into one-bit requests.
        for i in 0..last {
            *seq += 1;
            let byte = [(input.as_bytes()[complete] >> i) & 1];
            if key {
                owner.key(*seq, bits(&byte, 1))
            } else {
                owner.customization(*seq, bits(&byte, 1))
            }
            .unwrap();
        }
    }
}
fn check_case(
    id: u64,
    key: &[u8],
    key_last: u8,
    custom: &[u8],
    custom_last: u8,
    message: &[u8],
    message_last: u8,
    expected: &[u8],
    last: u8,
) {
    let authority = authority();
    let mut owner = Owner::new(&authority).unwrap();
    let mut seq = 1;
    owner
        .begin_setup(
            seq,
            id,
            bits(key, key_last).bit_len() as u128,
            bits(custom, custom_last).bit_len() as u128,
        )
        .unwrap();
    feed(&mut owner, &mut seq, bits(custom, custom_last), false);
    seq += 1;
    owner.finish_customization(seq).unwrap();
    feed(&mut owner, &mut seq, bits(key, key_last), true);
    seq += 1;
    owner.finish_setup(seq).unwrap();
    let complete = message.bit_len_hint(message_last);
    for chunk in message[..complete].chunks(37) {
        seq += 1;
        owner.update(seq, chunk).unwrap();
    }
    let tail = bits(
        &message[complete..],
        if complete == message.len() {
            0
        } else {
            message_last
        },
    );
    seq += 1;
    owner
        .finish(
            seq,
            tail,
            if id <= 2 { expected.len() } else { 0 },
            if id <= 2 { last } else { 0 },
        )
        .unwrap();
    let mut actual = vec![0; expected.len()];
    if id <= 2 {
        seq += 1;
        owner
            .export(seq, id, expected.len(), last, |out| {
                actual.copy_from_slice(out);
                true
            })
            .unwrap();
    } else {
        seq += 1;
        owner.squeeze(seq, 0, 0, false).unwrap();
        seq += 1;
        owner.export(seq, id, 0, 0, |out| out.is_empty()).unwrap();
        let mut pos = 0;
        while expected.len() - pos > 13 {
            seq += 1;
            owner.squeeze(seq, 13, 8, false).unwrap();
            seq += 1;
            owner
                .export(seq, id, 13, 8, |out| {
                    actual[pos..pos + 13].copy_from_slice(out);
                    true
                })
                .unwrap();
            pos += 13;
        }
        let width = expected.len() - pos;
        let last = if width == 0 { 0 } else { last };
        seq += 1;
        owner.squeeze(seq, width, last, true).unwrap();
        seq += 1;
        owner
            .export(seq, id, width, last, |out| {
                actual[pos..].copy_from_slice(out);
                true
            })
            .unwrap();
    }
    assert_eq!(actual, expected);
    assert_eq!(owner.phase, Phase::Empty);
    assert_eq!(owner.output, [0; 1024]);
    assert!(matches!(owner.state, State::Empty));
    assert!(authority.session().is_ok());
}
trait CompleteBytes {
    fn bit_len_hint(&self, last: u8) -> usize;
}
impl CompleteBytes for [u8] {
    fn bit_len_hint(&self, last: u8) -> usize {
        self.len()
            .saturating_sub(usize::from(!self.is_empty() && last != 8))
    }
}

#[test]
fn retained_rekey_and_verification() {
    use brynja_mac_kmac::{Fips202Output, Kmac128, Kmac256, KmacXof128, KmacXof256};
    for source in 1..=4 {
        for target in 1..=4 {
            for last in 1..=8 {
                let authority = authority();
                let mut owner = Owner::new(&authority).unwrap();
                owner.begin(1, source, whole(&[0xa5; 32]), empty()).unwrap();
                let mut seq = 2;
                owner
                    .finish(
                        seq,
                        empty(),
                        if source <= 2 { 33 } else { 0 },
                        if source <= 2 { last } else { 0 },
                    )
                    .unwrap();
                if source > 2 {
                    seq += 1;
                    owner.squeeze(seq, 33, last, true).unwrap();
                }
                let key_bytes = owner.output[..33].to_vec();
                let key = bits(&key_bytes, last);
                let custom_bytes = vec![0x37; 2050];
                let custom = whole(&custom_bytes);
                seq += 1;
                owner
                    .rekey_setup(seq, target, custom.bit_len() as u128)
                    .unwrap();
                feed(&mut owner, &mut seq, custom, false);
                seq += 1;
                owner.finish_customization(seq).unwrap();
                assert_eq!(owner.output, [0; 1024]);
                let mut expected = [0; 32];
                let out = Fips202Output::new(&mut expected, 8).unwrap();
                let reference = match target {
                    1 => Kmac128::new_bits(key, custom)
                        .unwrap()
                        .finalize_secret_bits(empty(), out)
                        .unwrap(),
                    2 => Kmac256::new_bits(key, custom)
                        .unwrap()
                        .finalize_secret_bits(empty(), out)
                        .unwrap(),
                    3 => KmacXof128::new_bits(key, custom)
                        .unwrap()
                        .finalize_bits_xof(empty())
                        .unwrap()
                        .squeeze_final_bits_secret(out)
                        .unwrap(),
                    _ => KmacXof256::new_bits(key, custom)
                        .unwrap()
                        .finalize_bits_xof(empty())
                        .unwrap()
                        .squeeze_final_bits_secret(out)
                        .unwrap(),
                };
                let expected = reference.expose();
                seq += 1;
                owner
                    .finish(
                        seq,
                        empty(),
                        if target <= 2 { 32 } else { 0 },
                        if target <= 2 { 8 } else { 0 },
                    )
                    .unwrap();
                if target <= 2 {
                    seq += 1;
                    assert!(owner.verify(seq, target, whole(&expected)).unwrap());
                } else {
                    seq += 1;
                    owner.squeeze(seq, 32, 8, true).unwrap();
                    seq += 1;
                    owner
                        .export(seq, target, 32, 8, |out| {
                            assert_eq!(out, expected);
                            true
                        })
                        .unwrap();
                }
                assert_eq!(owner.output, [0; 1024]);
            }
        }
    }
}
