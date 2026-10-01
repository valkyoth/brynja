//! Compile the real shipping encoder against the actual private worker decoder.
#![allow(dead_code)]
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
#[path = "sha3_batch_host_avx2_wire.rs"]
mod accelerated;
#[path = "sha3_batch_host_receipt.rs"]
mod sha3_batch_receipt;
#[path = "sha3_batch_host_wire.rs"]
mod sha3_batch_wire;
use super::sha3_batch_accelerated_wire::Header;
use sha3_batch_wire::Request;
fn compare(r: Request, input: &[u8]) {
    let mut raw = [0_u8; 304];
    let source = if input.is_empty() {
        0
    } else {
        input.as_ptr() as usize
    };
    let mut words = [0_u64; 38];
    words[36] = 1;
    words[..8].copy_from_slice(&[
        17,
        r.sequence,
        r.slot as u64,
        input.len() as u64,
        r.last as u64,
        source as u64,
        r.budget,
        0,
    ]);
    for (out, word) in words[12..36].iter_mut().zip(r.plan.into_iter().flatten()) {
        *out = word;
    }
    for (chunk, word) in raw.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    raw[64..80].copy_from_slice(&r.name_bits.to_le_bytes());
    raw[80..96].copy_from_slice(&r.custom_bits.to_le_bytes());
    let encoded = accelerated::header(r, input);
    assert_eq!(encoded.is_ok(), Header::decode(r.op, &raw).is_ok());
    if let Ok(encoded) = encoded {
        assert_eq!(encoded, raw);
    }
    assert_eq!(r.output_width(), if r.op == 98 { Some(1024) } else { None });
}
#[test]
fn shipping_avx2_encoder_and_worker_agree() {
    for op in 89..=100 {
        let base = Request {
            op,
            sequence: 1,
            plan: if matches!(op, 90 | 98) {
                [[2, 32, 8]; 8]
            } else {
                [[0; 3]; 8]
            },
            ..Request::default()
        };
        compare(base, &[]);
        for sequence in [0, 1, u64::MAX] {
            compare(Request { sequence, ..base }, &[]);
        }
        for slot in [0, 1, 7, 8, usize::MAX] {
            compare(Request { slot, ..base }, &[]);
        }
        for budget in [0, 1, u64::MAX] {
            compare(Request { budget, ..base }, &[]);
        }
        for bits in [0, 1, u64::MAX as u128, 1_u128 << 64, u128::MAX] {
            compare(
                Request {
                    name_bits: bits,
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
        for last in 0..=9 {
            for length in [0, 1, 1024, 1025] {
                compare(Request { last, ..base }, &std::vec![0;length]);
            }
        }
        for id in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, u64::MAX] {
            for width in [0, 1, 28, 32, 48, 64, 1024, 1025, u64::MAX] {
                for last in [0, 1, 7, 8, 9, 256] {
                    let mut changed = base;
                    changed.plan[0] = [id, width, last];
                    compare(changed, &[]);
                }
            }
        }
        compare(
            Request {
                plan: [[0; 3]; 8],
                ..base
            },
            &[],
        );
    }
}
