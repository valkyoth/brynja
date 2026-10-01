//! Focused Miri model of the actual bit packer; no cryptography or VBS execution.
#![forbid(unsafe_code)]
use brynja_hash_sha3::Fips202BitString as Bits;
#[derive(Debug, PartialEq, Eq)]
enum Error {
    Bits,
    Length,
    Crypto,
}
struct State<'a> {
    bytes: &'a mut Vec<u8>,
    tail: Vec<u8>,
    last: u8,
    fail: bool,
}
impl State<'_> {
    fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if self.fail {
            return Err(Error::Crypto);
        }
        self.bytes.extend_from_slice(input);
        Ok(())
    }
    fn finish(&mut self, input: Bits<'_>) -> Result<(), Error> {
        if self.fail {
            return Err(Error::Crypto);
        }
        self.tail = input.as_bytes().to_vec();
        self.last = input.valid_bits_in_last_byte();
        Ok(())
    }
}
// Include rather than reimplement: observe private pending storage in this test
// module while production visibility remains unchanged.
mod tuple_accelerated_packer {
    include!("tuple_accelerated_packer_body.rs");
    pub(super) fn pending(p: &Packer) -> ([u8; 1], u8) {
        (p.pending, p.used)
    }
}
use tuple_accelerated_packer::{Packer, pending};

#[test]
fn every_alignment_and_fragment_boundary_matches_independent_bit_packing() {
    for prefix in 0..8 {
        for width in [0, 1, 2, 7, 8, 9, 15, 16, 17, 31] {
            let input = [0b10110101, 0b10101010, 0b00110110, 0b01111111];
            let mut bytes = Vec::new();
            let mut state = State {
                bytes: &mut bytes,
                tail: vec![],
                last: 0,
                fail: false,
            };
            let mut p = Packer::new();
            let mut expected = vec![1; prefix];
            if prefix != 0 {
                p.append(
                    &mut state,
                    Bits::new(&[(1 << prefix) - 1], prefix as u8).unwrap(),
                )
                .unwrap();
            }
            let mut offset = 0;
            while offset < width {
                let n = (width - offset).min(3);
                let mut byte = 0;
                for bit in 0..n {
                    let v = (input[(offset + bit) / 8] >> ((offset + bit) % 8)) & 1;
                    byte |= v << bit;
                    expected.push(v);
                }
                p.append(&mut state, Bits::new(&[byte], n as u8).unwrap())
                    .unwrap();
                offset += n;
            }
            p.finish(&mut state).unwrap();
            let complete = expected.len() / 8;
            let packed: Vec<u8> = expected
                .chunks(8)
                .map(|chunk| {
                    chunk
                        .iter()
                        .enumerate()
                        .fold(0, |out, (i, bit)| out | (bit << i))
                })
                .collect();
            assert_eq!(state.bytes.as_slice(), &packed[..complete]);
            assert_eq!(state.tail, packed[complete..]);
            assert_eq!(state.last as usize, expected.len() % 8);
            assert_eq!(pending(&p), ([0], 0));
        }
    }
}
#[test]
fn failure_pending_storage_clears_before_reuse() {
    let mut bytes = Vec::new();
    let mut state = State {
        bytes: &mut bytes,
        tail: vec![],
        last: 0,
        fail: false,
    };
    let mut p = Packer::new();
    p.append(&mut state, Bits::new(&[7], 3).unwrap()).unwrap();
    assert_eq!(pending(&p), ([7], 3));
    state.fail = true;
    assert_eq!(p.finish(&mut state), Err(Error::Crypto));
    // The owner guard calls clear on failure. This focused model checks that
    // method and the actual packing code, not the surrounding owner protocol.
    p.clear();
    assert_eq!(pending(&p), ([0], 0));
    state.fail = false;
    p.append(&mut state, Bits::new(&[0xa5], 8).unwrap())
        .unwrap();
    p.finish(&mut state).unwrap();
    assert_eq!(state.bytes.as_slice(), &[0xa5]);
    assert!(state.tail.is_empty());
}
