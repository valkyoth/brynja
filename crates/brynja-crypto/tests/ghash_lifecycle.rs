//! Scoped public-API lifecycle checks. Inspect only live caller storage.
#![forbid(unsafe_code)]

use brynja_crypto::ghash::{Error, Ghash};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

// Use disjoint regions of one live allocation so we can also detect clearing
// a neighbour. The identity subkey makes the nonzero result known in advance.
const ONE: [u8; 16] = (1u128 << 127).to_be_bytes();
const BLOCK: [u8; 16] = [0x76; 16];
const GUARD: [u8; 16] = [0x9d; 16];
const OLD: [u8; 16] = [0xac; 16];
const ZERO: [u8; 16] = [0; 16];

fn storage() -> [[u8; 16]; 7] {
    [GUARD, ONE, OLD, GUARD, OLD, BLOCK, GUARD]
}

fn ended(output: [u8; 16]) -> [[u8; 16]; 7] {
    [GUARD, ONE, ZERO, GUARD, output, BLOCK, GUARD]
}

struct DeliberateUnwind;

#[test]
fn cancellation_and_incomplete_finish() -> Result<(), Error> {
    for finish in [false, true] {
        let mut arena = storage();
        let [_, key, work, _, out, block, _] = &mut arena;
        let mut hash = Ghash::new(key, work, 17);
        hash.update(block)?;
        hash.update(&[0x81])?;
        assert_eq!(hash.update(&[0x22]), Err(Error::LimitExceeded));
        if finish {
            assert!(matches!(hash.finish(out), Err(Error::PartialBlock)));
        } else {
            drop(hash);
        }
        assert_eq!(arena, ended(OLD));
    }
    Ok(())
}

#[test]
fn unwind_during_accumulation() {
    let mut arena = storage();
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
        let [_, key, work, _, _, block, _] = &mut arena;
        let mut hash = Ghash::new(key, work, 23);
        hash.update(block)?;
        hash.update(&[0x61; 7])?;
        resume_unwind(Box::new(DeliberateUnwind));
    }));
    assert!(result.is_err_and(|payload| payload.is::<DeliberateUnwind>()));
    assert_eq!(arena, ended(OLD));
}

#[test]
fn completed_output_lifetime() -> Result<(), Error> {
    for explicit in [false, true] {
        let mut arena = storage();
        let [_, key, work, _, out, block, _] = &mut arena;
        let mut hash = Ghash::new(key, work, 16);
        hash.update(block)?;
        let result = hash.finish(out)?;
        assert_eq!(work, &ZERO);
        assert_eq!(result.expose(), BLOCK);
        if explicit {
            result.clear();
        } else {
            drop(result);
        }
        assert_eq!(arena, ended(ZERO));
    }
    Ok(())
}

#[test]
fn unwind_with_readable_output() {
    let mut arena = storage();
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
        let [_, key, work, _, out, block, _] = &mut arena;
        let mut hash = Ghash::new(key, work, 16);
        hash.update(block)?;
        let result = hash.finish(out)?;
        assert_eq!(result.expose(), BLOCK);
        assert_eq!(work, &ZERO);
        resume_unwind(Box::new(DeliberateUnwind));
    }));
    assert!(result.is_err_and(|payload| payload.is::<DeliberateUnwind>()));
    assert_eq!(arena, ended(ZERO));
}
