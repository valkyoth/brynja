//! Test-only downstream replay of public vectors. Does not accept production keys.
#![forbid(unsafe_code)]
use brynja_mac_poly1305::OneTimeKey;
use std::io::{self, BufRead};

fn decode(field: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = field.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

fn replay(line: &str) -> Option<()> {
    let mut fields = line.split('\t');
    let mut key: [u8; 32] = decode(fields.next()?)?.try_into().ok()?;
    let msg = decode(fields.next()?)?;
    let expected: [u8; 16] = decode(fields.next()?)?.try_into().ok()?;
    if fields.next().is_some() {
        return None;
    }
    let mut mac = OneTimeKey::new(&mut key).start();
    for chunk in msg.chunks(31) {
        mac.update(chunk).ok()?;
    }
    (mac.finalize() == expected && key == [0; 32]).then_some(())
}

fn main() -> Result<(), &'static str> {
    let mut count = 0usize;
    for line in io::stdin().lock().lines() {
        replay(&line.map_err(|_| "input error")?).ok_or("vector mismatch or bad input")?;
        count += 1;
    }
    if count == 0 {
        return Err("empty corpus");
    }
    println!("matched {count} public vectors");
    Ok(())
}
