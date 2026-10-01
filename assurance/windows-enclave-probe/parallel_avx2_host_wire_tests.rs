//! Compile the actual shipping encoder against the private worker decoder.
#![allow(dead_code)]
use super::parallel_accelerated_wire::Header as Worker;
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
#[path = "parallel_host_avx2_wire.rs"]
mod parallel_avx2_wire;
#[path = "parallel_host_receipt.rs"]
mod parallel_receipt;
#[path = "parallel_host_wire.rs"]
mod parallel_wire;
use parallel_wire::Request;

fn compare(r: Request, input: &[u8]) {
    let source = if input.is_empty() {
        0
    } else {
        input.as_ptr() as usize
    };
    let mut raw = [0; 128];
    for (slot, word) in raw.chunks_exact_mut(8).zip([
        18,
        r.sequence,
        r.algorithm,
        r.block,
        r.budget,
        r.custom_bits as u64,
        (r.custom_bits >> 64) as u64,
        input.len() as u64,
        u64::from(r.last),
        r.width as u64,
        u64::from(r.output_last),
        u64::from(r.terminal),
        source as u64,
        0,
        1,
        0,
    ]) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    let encoded = parallel_avx2_wire::header(r, input);
    assert_eq!(encoded.is_ok(), Worker::decode(r.op, &raw).is_ok());
    if let Ok(bytes) = encoded {
        assert_eq!(bytes, raw);
        assert!(Worker::decode(r.op, &bytes).is_ok());
    }
}
#[test]
fn shipping_avx2_encoder_and_worker_agree() {
    for op in 99..=109 {
        for id in 0..=5 {
            for block in [0, 1, 8, u64::MAX] {
                let base = Request {
                    op,
                    sequence: 1,
                    algorithm: id,
                    block,
                    ..Request::default()
                };
                for length in [0, 1, 1024, 1025] {
                    for last in 0..=9 {
                        compare(Request { last, ..base }, &std::vec![0; length]);
                    }
                }
                for width in [0, 1, 32, 1024, 1025] {
                    for output_last in 0..=9 {
                        for terminal in [false, true] {
                            compare(
                                Request {
                                    width,
                                    output_last,
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
                            custom_bits: bits,
                            ..base
                        },
                        &[],
                    );
                }
                for budget in [0, 1, u64::MAX] {
                    compare(Request { budget, ..base }, &[]);
                }
                for sequence in [0, u64::MAX] {
                    compare(Request { sequence, ..base }, &[]);
                }
            }
        }
    }
}
