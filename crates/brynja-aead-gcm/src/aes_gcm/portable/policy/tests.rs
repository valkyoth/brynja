extern crate std;

use super::*;
use crate::aes::{self, Aes128ExpandedKey, SecretBlock};
use core::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn aes(storage: &mut [u8; 176]) -> Result<Aes128ExpandedKey<'_>, Error> {
    Aes128ExpandedKey::new(&[0; 16], storage).map_err(Error::Aes)
}

fn one_tag<const T: usize>() -> Result<(), Error> {
    let mut storage = [0; 176];
    let mut key = Key::<_, T>::from_reserved_range(aes(&mut storage)?, [0; 4], 0, 1)?;
    let (mut buf, mut scratch) = ([0; 16], [0xcc; 16]);
    let (iv, tag) = key.seal_next(&[], Buffers::InPlace(&mut buf), &mut scratch)?;
    assert_eq!(iv, [0; 12]);
    assert_eq!(buf, 0x0388dace60b6a392f328c2b971b2fe78u128.to_be_bytes());
    let full = 0xab6e47d42cec13bdf53a67b21257bddfu128.to_be_bytes();
    assert_eq!(Some(&tag), full.first_chunk::<T>());
    assert_eq!(scratch, [0; 16]);
    let ciphertext = buf;
    for i in 0..T {
        let mut wrong = tag;
        *wrong.get_mut(i).ok_or(Error::Invariant)? ^= 1;
        assert_eq!(
            key.open(&iv, &[], &wrong, Buffers::InPlace(&mut buf), &mut scratch),
            Err(Error::Authentication)
        );
        assert_eq!(buf, ciphertext);
        assert_eq!(scratch, [0; 16]);
    }
    key.open(&iv, &[], &tag, Buffers::InPlace(&mut buf), &mut scratch)?;
    assert_eq!(buf, [0; 16]);
    assert_eq!(
        key.seal_next(&[], Buffers::InPlace(&mut buf), &mut scratch),
        Err(Error::Exhausted)
    );
    Ok(())
}

#[test]
fn every_admitted_tag_matches_published_prefix_in_place() -> Result<(), Error> {
    one_tag::<12>()?;
    one_tag::<13>()?;
    one_tag::<14>()?;
    one_tag::<15>()?;
    one_tag::<16>()
}

#[test]
fn invalid_tag_and_nonce_allocations_are_rejected() -> Result<(), Error> {
    for rejected in [
        TagPolicy::<0>::new().err(),
        TagPolicy::<4>::new().err(),
        TagPolicy::<8>::new().err(),
        TagPolicy::<11>::new().err(),
        TagPolicy::<17>::new().err(),
    ] {
        assert_eq!(rejected, Some(Error::TagLength));
    }
    let mut storage = [0; 176];
    for (first, count) in [(0, 0), (u64::MAX, 2)] {
        assert_eq!(
            Key::<_, 16>::from_reserved_range(aes(&mut storage)?, [1; 4], first, count).err(),
            Some(Error::Length)
        );
        assert_eq!(storage, [0; 176]);
    }
    Ok(())
}

#[test]
fn key_wide_and_short_iv_limits_never_wrap() -> Result<(), Error> {
    fn valid<const N: usize>(prefix: &[u8], first: u32, count: u64) -> bool {
        let mut storage = [0; 176];
        aes(&mut storage)
            .and_then(|cipher| {
                Key::<_, 16, N>::from_reserved_invocations(cipher, prefix, first, count)
            })
            .is_ok()
    }
    assert!(!valid::<0>(&[], 0, 1));
    assert!(!valid::<8>(&[1; 3], 0, 1));
    assert!(!valid::<8>(&[1; 5], 0, 1));
    assert!(!valid::<8>(&[1; 4], 0, 0));
    for (count, expected) in [
        (1u64 << 32, true),
        ((1u64 << 32) + 1, false),
        (u64::MAX, false),
    ] {
        assert_eq!(valid::<8>(&[1; 4], 0, count), expected);
    }
    assert!(valid::<2>(&[], 0xffff, 1));
    assert!(!valid::<2>(&[], 0xffff, 2));
    assert!(valid::<3>(&[], 0xff_ffff, 1));
    assert!(!valid::<3>(&[], 0x100_0000, 1));
    assert!(!valid::<12>(&[0; 4], u32::MAX, 2));
    let mut storage = [0; 176];
    let mut short = Key::<_, 16, 1>::from_reserved_invocations(aes(&mut storage)?, &[], 254, 2)?;
    assert_eq!(
        short.seal_next(&[], Buffers::InPlace(&mut [1]), &mut []),
        Err(Error::Length)
    );
    for byte in [254, 255] {
        assert_eq!(
            short.seal_next(&[], Buffers::InPlace(&mut []), &mut [])?.0,
            [byte]
        );
    }
    assert_eq!(
        short.seal_next(&[], Buffers::InPlace(&mut []), &mut []),
        Err(Error::Exhausted)
    );
    drop(short);
    // A carry in a four-byte invocation must not change the caller's prefix.
    let prefix = crate::aes_gcm::tests::sample_iv::<3>();
    let first = 0x1234_ffff_u32;
    let mut sender =
        Key::<_, 16, 7>::from_reserved_invocations(aes(&mut storage)?, &prefix, first, 2)?;
    for invocation in [first, 0x1235_0000] {
        let (iv, _) = sender.seal_next(&[], Buffers::InPlace(&mut []), &mut [])?;
        assert_eq!(&iv[..3], &prefix);
        assert_eq!(&iv[3..], &invocation.to_be_bytes());
    }
    drop(sender);
    let mut mixed =
        Key::<_, 16, 12>::from_reserved_invocations(aes(&mut storage)?, b"test", u32::MAX, 1)?;
    assert_eq!(
        &mixed.seal_next(&[], Buffers::InPlace(&mut []), &mut [])?.0,
        b"test\x00\x00\x00\x00\xff\xff\xff\xff"
    );
    assert_eq!(
        mixed.seal_next(&[], Buffers::InPlace(&mut []), &mut []),
        Err(Error::Exhausted)
    );
    Ok(())
}

#[test]
fn last_nonce_is_usable_once_and_public_rejections_do_not_burn_it() -> Result<(), Error> {
    let mut storage = [0; 176];
    let mut key =
        Key::<_, 16>::from_reserved_range(aes(&mut storage)?, [0x3a; 4], u64::MAX - 1, 2)?;
    let (mut data, mut scratch) = ([0x45; 17], [0xee; 17]);
    assert_eq!(
        key.seal_next(&[], Buffers::InPlace(&mut data), &mut []),
        Err(Error::Length)
    );
    assert_eq!(
        key.seal_next(&[], Buffers::Separate(&[], &mut data), &mut scratch),
        Err(Error::Length)
    );
    assert_eq!(data, [0x45; 17]);
    assert_eq!(scratch, [0xee; 17]);
    let (iv0, tag0) = key.seal_next(
        b"aad",
        Buffers::Separate(&[0x27; 17], &mut data),
        &mut scratch,
    )?;
    assert_eq!(&iv0[..4], &[0x3a; 4]);
    assert_eq!(&iv0[4..], &(u64::MAX - 1).to_be_bytes());
    let mut plain = [0xff; 17];
    key.open(
        &iv0,
        b"aad",
        &tag0,
        Buffers::Separate(&data, &mut plain),
        &mut scratch,
    )?;
    assert_eq!(plain, [0x27; 17]);
    let (iv1, _) = key.seal_next(&[], Buffers::InPlace(&mut []), &mut [])?;
    assert_eq!(&iv1[4..], &u64::MAX.to_be_bytes());
    assert_eq!(
        key.seal_next(&[], Buffers::InPlace(&mut []), &mut []),
        Err(Error::Exhausted)
    );
    Ok(())
}

// One armed failure at the second payload block (after H, mask, first payload).
struct Interrupt<K> {
    inner: K,
    left: Cell<Option<u8>>,
    unwind: bool,
}
impl<K: Forward> Forward for Interrupt<K> {
    fn hash_route(&self) -> &impl crate::aes_gcm::HashRoute {
        self.inner.hash_route()
    }
    fn encrypt<'a>(&self, input: &Block, out: &'a mut Block) -> Result<SecretBlock<'a>, Error> {
        if let Some(left) = self.left.get() {
            self.left.set(left.checked_sub(1));
            if left == 0 {
                if self.unwind {
                    std::panic::resume_unwind(std::boxed::Box::new(()));
                }
                return Err(Error::Aes(aes::Error::SecretMemory));
            }
        }
        self.inner.encrypt(input, out)
    }
}

#[test]
fn last_general_iv_is_spent_on_keyed_failure_or_unwind() -> Result<(), Error> {
    for unwind in [false, true] {
        let mut storage = [0; 176];
        let cipher = Interrupt {
            inner: aes(&mut storage)?,
            left: Cell::new(Some(3)),
            unwind,
        };
        let mut sender = Key::<_, 16, 8>::from_reserved_invocations(cipher, b"test", u32::MAX, 1)?;
        let (mut dst, mut scratch) = ([0xaa; 17], [0xff; 17]);
        let result = catch_unwind(AssertUnwindSafe(|| {
            sender.seal_next(&[], Buffers::Separate(&[0x11; 17], &mut dst), &mut scratch)
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.map_err(|_| Error::Invariant)?,
                Err(Error::Aes(aes::Error::SecretMemory))
            );
        }
        assert_eq!(dst, [0xaa; 17]);
        assert_eq!(scratch, [0; 17]);
        assert_eq!(
            sender.seal_next(&[], Buffers::InPlace(&mut []), &mut []),
            Err(Error::Exhausted)
        );
    }
    Ok(())
}

#[test]
fn keyed_error_or_unwind_burns_nonce_but_never_commits_partial_output() -> Result<(), Error> {
    for unwind in [false, true] {
        let mut storage = [0; 176];
        let cipher = Interrupt {
            inner: aes(&mut storage)?,
            left: Cell::new(Some(3)),
            unwind,
        };
        let mut key = Key::<_, 12>::from_reserved_range(cipher, [0; 4], 5, 2)?;
        let (mut data, mut work) = ([0x39; 17], [0xaa; 17]);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            key.seal_next(&[], Buffers::InPlace(&mut data), &mut work)
        }));
        if unwind {
            assert!(outcome.is_err());
        } else {
            assert_eq!(
                outcome.map_err(|_| Error::Invariant)?,
                Err(Error::Aes(aes::Error::SecretMemory))
            );
        }
        assert_eq!(data, [0x39; 17]);
        assert_eq!(work, [0; 17]);
        let (iv, tag) = key.seal_next(&[], Buffers::InPlace(&mut data), &mut work)?;
        assert_eq!(&iv[4..], &6u64.to_be_bytes());
        let ciphertext = data;
        key.cipher.left.set(Some(3));
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            key.open(&iv, &[], &tag, Buffers::InPlace(&mut data), &mut work)
        }));
        if unwind {
            assert!(outcome.is_err());
        } else {
            assert_eq!(
                outcome.map_err(|_| Error::Invariant)?,
                Err(Error::Aes(aes::Error::SecretMemory))
            );
        }
        assert_eq!(data, ciphertext);
        assert_eq!(work, [0; 17]);
    }
    Ok(())
}
