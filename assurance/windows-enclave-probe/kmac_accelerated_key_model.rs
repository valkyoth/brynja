//! Memory/bit-packing model only: the actual Key implementation with a
//! noncryptographic byte sink. Does not execute AVX2 or qualify enclave storage.
extern crate self as sha3_accelerated_state;
use brynja_hash_sha3::Fips202BitString;
use core::marker::PhantomData;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Bits,
    Crypto,
    State,
}
pub struct State<'a> {
    bytes: Vec<u8>,
    fail: bool,
    lifetime: PhantomData<&'a ()>,
}
impl State<'_> {
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if self.fail {
            return Err(Error::Crypto);
        }
        self.bytes.extend_from_slice(input);
        Ok(())
    }
}
#[path = "kmac_accelerated_key.rs"]
mod key;
fn sink() -> State<'static> {
    State {
        bytes: Vec::new(),
        fail: false,
        lifetime: PhantomData,
    }
}

#[test]
fn actual_key_framing_matches_independent_bytepad() {
    use brynja_hash_sha3::left_encode_u128;
    for rate in [136, 168] {
        for count in [0, 1, 7, 8, 9, 128, 129, 255, 256, 257, 1345] {
            let mut bytes = vec![0x95; (count + 7) / 8];
            if count % 8 != 0 {
                *bytes.last_mut().unwrap() &= 0xff >> (8 - count % 8);
            }
            let mut expected = left_encode_u128(rate as u128).as_bytes().to_vec();
            expected.extend_from_slice(left_encode_u128(count as u128).as_bytes());
            expected.extend_from_slice(&bytes);
            expected.resize(expected.len().div_ceil(rate) * rate, 0);
            for fragmented in [false, true] {
                let mut state = sink();
                let mut frame = key::Key::new(&mut state, count as u128, rate).unwrap();
                if fragmented {
                    for bit in 0..count {
                        let value = [(bytes[bit / 8] >> (bit % 8)) & 1];
                        frame
                            .push(&mut state, Fips202BitString::new(&value, 1).unwrap())
                            .unwrap();
                    }
                } else {
                    frame
                        .push(
                            &mut state,
                            Fips202BitString::new(
                                &bytes,
                                if count == 0 {
                                    0
                                } else {
                                    ((count - 1) % 8 + 1) as u8
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                }
                frame.finish(&mut state).unwrap();
                assert_eq!(state.bytes, expected);
            }
        }
    }
}
#[test]
fn actual_key_completion_and_absorb_failure_reject() {
    let mut state = sink();
    let mut frame = key::Key::new(&mut state, 8, 136).unwrap();
    let before = state.bytes.clone();
    assert_eq!(frame.finish(&mut state), Err(Error::State));
    assert_eq!(
        frame.push(&mut state, Fips202BitString::new(&[1; 2], 8).unwrap()),
        Err(Error::Length)
    );
    assert_eq!(state.bytes, before);
    state.fail = true;
    assert_eq!(
        frame.push(&mut state, Fips202BitString::new(&[1], 8).unwrap()),
        Err(Error::Crypto)
    );
    assert_eq!(state.bytes, before);
}
