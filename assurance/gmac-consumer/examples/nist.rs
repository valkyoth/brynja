//! Host-only decoder for public GMAC response data.
#![forbid(unsafe_code)]

use gmac_consumer::{Operation, replay};
use std::io::{self, BufRead};

fn bytes(field: &str) -> Option<Vec<u8>> {
    let (pairs, tail) = field.as_bytes().as_chunks::<2>();
    if !tail.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

fn check<const T: usize>(
    op: Operation,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> Option<bool> {
    let tag: &[u8; T] = tag.try_into().ok()?;
    match iv.len() {
        1 => replay::<T, 1>(op, key, iv.try_into().ok()?, aad, tag),
        3 => replay::<T, 3>(op, key, iv.try_into().ok()?, aad, tag),
        4 => replay::<T, 4>(op, key, iv.try_into().ok()?, aad, tag),
        5 => replay::<T, 5>(op, key, iv.try_into().ok()?, aad, tag),
        8 => replay::<T, 8>(op, key, iv.try_into().ok()?, aad, tag),
        11 => replay::<T, 11>(op, key, iv.try_into().ok()?, aad, tag),
        12 => replay::<T, 12>(op, key, iv.try_into().ok()?, aad, tag),
        13 => replay::<T, 13>(op, key, iv.try_into().ok()?, aad, tag),
        15 => replay::<T, 15>(op, key, iv.try_into().ok()?, aad, tag),
        16 => replay::<T, 16>(op, key, iv.try_into().ok()?, aad, tag),
        17 => replay::<T, 17>(op, key, iv.try_into().ok()?, aad, tag),
        128 => replay::<T, 128>(op, key, iv.try_into().ok()?, aad, tag),
        129 => replay::<T, 129>(op, key, iv.try_into().ok()?, aad, tag),
        _ => return None,
    }
    .ok()
}

fn row(line: &str) -> Option<usize> {
    let mut fields = line.split('\t');
    let (op, index) = match fields.next()? {
        "seal" => (Operation::Generate, 0),
        "open" => (Operation::Verify, 1),
        "reject" => (Operation::Reject, 2),
        _ => return None,
    };
    let key = bytes(fields.next()?)?;
    let iv = bytes(fields.next()?)?;
    let aad = bytes(fields.next()?)?;
    let tag = bytes(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    let ok = match tag.len() {
        12 => check::<12>(op, &key, &iv, &aad, &tag),
        13 => check::<13>(op, &key, &iv, &aad, &tag),
        14 => check::<14>(op, &key, &iv, &aad, &tag),
        15 => check::<15>(op, &key, &iv, &aad, &tag),
        16 => check::<16>(op, &key, &iv, &aad, &tag),
        _ => None,
    }?;
    ok.then_some(index)
}

fn main() {
    let mut totals = [0usize; 3];
    for (n, line) in io::stdin().lock().lines().enumerate() {
        let index = row(&line.expect("read public fixture"))
            .unwrap_or_else(|| panic!("GMAC case {} failed", n + 1));
        totals[index] += 1;
    }
    let [generate, verify, reject] = totals;
    println!("generate={generate} verify={verify} reject={reject}");
}
