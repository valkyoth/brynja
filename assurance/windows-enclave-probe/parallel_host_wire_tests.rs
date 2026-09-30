#[derive(Debug)]
enum Error {
    Bounds,
}
#[path = "parallel_host_wire.rs"]
mod parallel_wire;
use super::parallel_stream_wire::Header;
use parallel_wire::Request;
fn compare(r: Request, input: &[u8]) {
    let mut raw = [0; 112];
    for (word, bytes) in [
        12,
        r.sequence,
        r.algorithm,
        r.block,
        r.budget,
        0,
        0,
        input.len() as u64,
        u64::from(r.last),
        r.width as u64,
        u64::from(r.output_last),
        u64::from(r.terminal),
        if input.is_empty() {
            0
        } else {
            input.as_ptr() as u64
        },
        0,
    ]
    .into_iter()
    .zip(raw.chunks_exact_mut(8))
    {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    raw[40..56].copy_from_slice(&r.custom_bits.to_le_bytes());
    let result = r.header(input);
    assert_eq!(result.is_ok(), Header::decode(r.op, &raw).is_ok());
    if let Ok(actual) = result {
        assert_eq!(actual, raw);
    }
    assert_eq!(
        r.output_width(),
        if r.op == 106 { Some(r.width) } else { None }
    );
}
#[test]
fn host_and_worker_metadata_agree() {
    for op in 99..=109 {
        let base = Request {
            op,
            sequence: 1,
            algorithm: if matches!(op, 100 | 106 | 108) { 1 } else { 0 },
            block: if matches!(op, 100 | 108) { 8 } else { 0 },
            ..Request::default()
        };
        compare(base, &[]);
        for sequence in [0, 1, u64::MAX] {
            compare(Request { sequence, ..base }, &[]);
        }
        for algorithm in 0..=5 {
            compare(Request { algorithm, ..base }, &[]);
        }
        for block in [0, 1, u64::MAX] {
            compare(Request { block, ..base }, &[]);
        }
        for budget in [0, 1, u64::MAX] {
            compare(Request { budget, ..base }, &[]);
        }
        for custom_bits in [0, 1, u128::MAX] {
            compare(
                Request {
                    custom_bits,
                    ..base
                },
                &[],
            );
        }
        for last in 0..=9 {
            for length in [0, 1, 1024, 1025] {
                compare(Request { last, ..base }, &std::vec![0;length]);
            }
            for width in [0, 1, 1024, 1025] {
                for terminal in [false, true] {
                    compare(
                        Request {
                            width,
                            output_last: last,
                            terminal,
                            ..base
                        },
                        &[],
                    );
                }
            }
        }
    }
}
