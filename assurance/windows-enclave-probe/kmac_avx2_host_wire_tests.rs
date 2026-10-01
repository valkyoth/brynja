//! Compile the actual shipping encoder against the private worker decoder.
#![allow(dead_code)]
use super::kmac_accelerated_wire::Header as Worker;
#[derive(Debug)]
enum Error {
    Bounds,
    Protocol,
}
mod protocol {
    pub fn regions(_: usize, _: [usize; 2], _: [usize; 2]) -> bool {
        true
    }
}
#[path = "kmac_host_avx2_wire.rs"]
mod kmac_avx2_wire;
#[path = "kmac_host_wire.rs"]
mod kmac_wire;
use kmac_wire::Request;

fn compare(r: Request, input: &[u8]) {
    let source = if input.is_empty() {
        0
    } else {
        input.as_ptr() as usize
    };
    let mut raw = [0; 112];
    for (slot, word) in raw.chunks_exact_mut(8).zip([
        15,
        r.sequence,
        r.algorithm,
        input.len() as u64,
        u64::from(r.last),
        source as u64,
        r.width as u64,
        u64::from(r.terminal),
        r.key_bits as u64,
        (r.key_bits >> 64) as u64,
        r.custom_bits as u64,
        (r.custom_bits >> 64) as u64,
        1,
        0,
    ]) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    let encoded = kmac_avx2_wire::header(r, input);
    assert_eq!(encoded.is_ok(), Worker::decode(r.op, &raw).is_ok());
    if let Ok(bytes) = encoded {
        assert_eq!(bytes, raw);
        assert!(Worker::decode(r.op, &bytes).is_ok());
    }
}
#[test]
fn shipping_avx2_encoder_and_worker_agree() {
    for op in 39..=52 {
        let base = Request {
            op,
            sequence: 1,
            ..Request::default()
        };
        for id in 0..=5 {
            let base = Request {
                algorithm: id,
                ..base
            };
            for length in [0, 1, 1024, 1025] {
                for last in 0..=9 {
                    compare(Request { last, ..base }, &std::vec![0; length]);
                }
            }
            for width in [0, 1, 32, 1024, 1025, 8192, 8193] {
                for last in 0..=9 {
                    for terminal in [false, true] {
                        compare(
                            Request {
                                width,
                                last,
                                terminal,
                                ..base
                            },
                            &[],
                        );
                    }
                }
            }
            for bits in [0, 1, u64::MAX as u128, 1_u128 << 64, u128::MAX] {
                compare(
                    Request {
                        key_bits: bits,
                        ..base
                    },
                    &[],
                );
                compare(
                    Request {
                        custom_bits: bits,
                        ..base
                    },
                    &[],
                );
            }
            compare(
                Request {
                    sequence: 0,
                    ..base
                },
                &[],
            );
            compare(
                Request {
                    sequence: u64::MAX,
                    ..base
                },
                &[],
            );
        }
    }
}
