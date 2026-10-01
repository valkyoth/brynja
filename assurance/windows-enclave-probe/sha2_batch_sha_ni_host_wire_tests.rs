//! Exact host encoder / real enclave decoder parity, including rejected inputs.
#![allow(dead_code)]
#[derive(Debug)]
enum Error {
    Bounds,
    Protocol,
}
#[path = "sha2_batch_host_sha_ni_wire.rs"]
mod accelerated;
#[path = "sha2_batch_host_receipt.rs"]
mod sha2_batch_receipt;
#[path = "sha2_batch_host_wire.rs"]
mod sha2_batch_wire;
mod protocol {
    pub fn regions(_: usize, _: [usize; 2], _: [usize; 2]) -> bool {
        true
    }
}
use super::sha2_batch_accelerated_wire::Header;
use sha2_batch_wire::Request;
fn compare(request: Request, input: &[u8]) {
    let source = if input.is_empty() {
        0
    } else {
        input.as_ptr() as usize
    };
    let mut words = [0_u64; 18];
    words[16] = 1;
    words[..8].copy_from_slice(&[
        19,
        request.sequence,
        request.slot as u64,
        input.len() as u64,
        u64::from(request.last),
        source as u64,
        request.budget,
        0,
    ]);
    words[8..16].copy_from_slice(&request.plan);
    let mut raw = [0; 144];
    for (word, chunk) in words.iter().zip(raw.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    let header = accelerated::header(request, input);
    assert_eq!(header.is_ok(), Header::decode(request.op, &raw).is_ok());
    if let Ok(header) = header {
        assert_eq!(header, raw);
    }
    assert_eq!(
        request.output_width(),
        if request.op == 85 { Some(512) } else { None }
    );
}
#[test]
fn shipping_sha_ni_encoder_and_worker_agree() {
    for op in 79..=87 {
        let base = Request {
            op,
            sequence: 1,
            plan: if matches!(op, 80 | 85) {
                [2; 8]
            } else {
                [0; 8]
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
        for last in 0..=9 {
            for length in [0, 1, 1024, 1025] {
                compare(Request { last, ..base }, &std::vec![0; length]);
            }
        }
        for identity in [
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            0x1000,
            0x1001,
            0x117f,
            0x1180,
            0x1181,
            0x11ff,
            0x1200,
            u64::MAX,
        ] {
            for slot in 0..8 {
                let mut request = base;
                request.plan[slot] = identity;
                compare(request, &[]);
            }
        }
        compare(
            Request {
                plan: [0; 8],
                ..base
            },
            &[],
        );
    }
}
