//! Compile the future host encoder against the actual enclave decoder.
#[derive(Debug)]
enum Error {
    Bounds,
}
#[path = "tuple_host_wire.rs"]
mod tuple_wire;
use super::tuple_stream_wire::Header;
use std::vec;
use tuple_wire::Request;

fn compare(request: Request, input: &[u8]) {
    // Independently construct metadata, including requests the host rejects.
    let mut raw = [0_u8; 96];
    let source = if input.is_empty() {
        0
    } else {
        input.as_ptr() as usize
    };
    for (word, bytes) in [
        9,
        request.sequence,
        request.algorithm,
        input.len() as u64,
        u64::from(request.last),
        source as u64,
        request.width as u64,
        u64::from(request.terminal),
    ]
    .into_iter()
    .zip(raw.chunks_exact_mut(8))
    {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    raw[64..80].copy_from_slice(&request.item_bits.to_le_bytes());
    raw[80..96].copy_from_slice(&request.custom_bits.to_le_bytes());
    let encoded = request.header(input);
    assert_eq!(encoded.is_ok(), Header::decode(request.op, &raw).is_ok());
    if let Ok(encoded) = encoded {
        assert_eq!(encoded, raw);
    }
    assert_eq!(
        request.output_width(),
        if request.op == 68 {
            Some(request.width)
        } else {
            None
        }
    );
}

#[test]
fn host_and_enclave_metadata_agree() {
    for op in 59..=71 {
        let base = Request {
            op,
            sequence: 1,
            algorithm: if matches!(op, 60 | 68 | 69) { 1 } else { 0 },
            ..Request::default()
        };
        compare(base, &[]);
        for sequence in [0, 1, u64::MAX] {
            compare(Request { sequence, ..base }, &[]);
        }
        for algorithm in 0..=5 {
            compare(Request { algorithm, ..base }, &[]);
        }
        for last in 0..=9 {
            for width in [0, 1, 1024, 1025] {
                for terminal in [false, true] {
                    compare(
                        Request {
                            last,
                            width,
                            terminal,
                            ..base
                        },
                        &[],
                    );
                }
            }
            for length in [0, 1, 1024, 1025] {
                compare(Request { last, ..base }, &vec![0; length]);
            }
        }
        for bits in [0, 1, u128::from(u64::MAX) + 1, u128::MAX] {
            compare(
                Request {
                    item_bits: bits,
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
    }
}
