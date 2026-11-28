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
    // These are public fixtures only. Exercise the actual consuming verifier,
    // both outcomes, and caller-visible key clearing in this linked executable.
    let mut valid_key = key;
    let mut invalid_key = key;
    let mut mac = OneTimeKey::new(&mut key).start();
    for chunk in msg.chunks(31) {
        mac.update(chunk).ok()?;
    }
    if mac.finalize() != expected || key != [0; 32] {
        return None;
    }
    let mut wrong = expected;
    wrong[15] ^= 1;
    let good = verify_record(&mut valid_key, &msg, &expected);
    let bad = verify_record(&mut invalid_key, &msg, &wrong);
    (good == Ok(())
        && bad == Err(brynja_mac_poly1305::Error::Authentication)
        && valid_key == [0; 32]
        && invalid_key == [0; 32])
        .then_some(())
}

#[inline(never)]
fn verify_record(
    key: &mut [u8; 32],
    msg: &[u8],
    tag: &[u8; 16],
) -> Result<(), brynja_mac_poly1305::Error> {
    let mut mac = OneTimeKey::new(key).start();
    mac.update(msg)?;
    mac.verify(tag)
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
