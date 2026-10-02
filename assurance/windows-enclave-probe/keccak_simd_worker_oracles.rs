//! Independent vectors run through the actual worker with bounded OS-copy doubles.
use super::keccak_simd_worker_tests::*;
use super::*;
use std::boxed::Box;
fn decode(text: &str) -> std::vec::Vec<u8> {
    if text == "-" {
        return std::vec![];
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn independent_oracles_through_worker() {
    let rows: std::vec::Vec<_> = include_str!("keccak-simd-vectors.txt").lines().collect();
    assert_eq!(rows.len(), 2080);
    for rows in rows.chunks_exact(4) {
        let mut layout = [(0, 0, 0, 0, 0); 4];
        let mut expected = [0; 1024];
        for (lane, row) in rows.iter().enumerate() {
            let f: std::vec::Vec<_> = row.split_whitespace().collect();
            layout[lane] = (
                f[0].parse().unwrap(),
                f[7].parse().unwrap(),
                f[1].parse().unwrap(),
                f[3].parse().unwrap(),
                f[5].parse().unwrap(),
            );
            let answer = decode(f[8]);
            expected[lane * 256..lane * 256 + answer.len()].copy_from_slice(&answer);
        }
        let mut page = Box::new(Page::empty());
        let pointer = (&mut *page as *mut Page).cast();
        assert_eq!(invoke(0, pointer), 1);
        request(DIGEST, 1, layout);
        // Confirm the generator and OS-copy-double inputs are byte-identical.
        for (lane, row) in rows.iter().enumerate() {
            let f: std::vec::Vec<_> = row.split_whitespace().collect();
            for (part, column) in [2, 4, 6].into_iter().enumerate() {
                assert_eq!(
                    IO.lock().unwrap().payload[lane * 3 + part],
                    decode(f[column])
                );
            }
        }
        assert_eq!(invoke(DIGEST, pointer), success(DIGEST));
        request(EXPORT, 2, layout);
        assert_eq!(invoke(EXPORT, pointer), success(EXPORT));
        assert_eq!(IO.lock().unwrap().output, expected, "layout={layout:?}");
        destroy(pointer);
    }
}
