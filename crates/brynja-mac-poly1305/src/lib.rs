//! Standalone RFC 8439 Poly1305. A fresh, secret 32-byte key is required
//! for **each message**. This MAC neither encrypts nor derives one-time keys.
#![no_std]
#![forbid(unsafe_code)]

mod field;

use brynja_core::{
    accumulate_secret_byte_difference, clear_owned_region, secret_difference_is_zero,
};

/// A single-use key. The exclusively borrowed bytes are cleared on drop,
/// including after a message finishes. Copies made by the caller are not.
///
/// ```compile_fail,E0382
/// use brynja_mac_poly1305::OneTimeKey;
/// fn invalid(key: OneTimeKey<'_>) {
///     let _tag = key.start().finalize();
///     let _second_message = key.start(); // the key has already been consumed
/// }
/// ```
#[must_use = "dropping the key clears its storage"]
pub struct OneTimeKey<'a>(&'a mut [u8; 32]);

impl<'a> OneTimeKey<'a> {
    /// Take responsibility for clearing the supplied one-time key storage.
    pub fn new(storage: &'a mut [u8; 32]) -> Self {
        Self(storage)
    }

    /// Consume this key to start exactly one message.
    pub fn start(self) -> Poly1305<'a> {
        Poly1305 {
            key: self,
            acc: [[0; 8]; 5],
            tail: [0; 16],
            used: 0,
            length: 0,
        }
    }
}

impl Drop for OneTimeKey<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0);
    }
}

/// Failure returned by the authenticator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The cumulative message length would exceed u64::MAX bytes.
    TooLong,
    /// The full 16-byte tag did not match.
    Authentication,
}

/// The state of one message. No reset, clone, heap allocation or tag truncation.
/// Dropping it clears retained accumulator, tail and key storage. This guarantee
/// does not extend to registers, compiler-generated copies, aborts or forgotten owners.
#[must_use = "finish or verify the message; dropping abandons it and clears the key"]
pub struct Poly1305<'a> {
    key: OneTimeKey<'a>,
    acc: [[u8; 8]; 5],
    tail: [u8; 16],
    used: usize,
    length: u64,
}

impl Poly1305<'_> {
    /// Append message bytes. A length error leaves the entire state unchanged.
    pub fn update(&mut self, mut input: &[u8]) -> Result<(), Error> {
        self.length = self
            .length
            .checked_add(u64::try_from(input.len()).map_err(|_| Error::TooLong)?)
            .ok_or(Error::TooLong)?;
        let (r, _) = self.key.0.split_at(16);
        if self.used != 0 {
            let (_, room) = self.tail.split_at_mut(self.used);
            let take = room.len().min(input.len());
            let (prefix, rest) = input.split_at(take);
            room.split_at_mut(take).0.copy_from_slice(prefix);
            self.used = self.used.wrapping_add(take); // at most 16
            if self.used < 16 {
                return Ok(());
            }
            field::absorb(&mut self.acc, r, &self.tail, true);
            let _ = clear_owned_region(&mut self.tail);
            input = rest;
        }
        let (blocks, rest) = input.as_chunks::<16>();
        for block in blocks {
            field::absorb(&mut self.acc, r, block, true);
        }
        self.used = rest.len();
        self.tail.split_at_mut(self.used).0.copy_from_slice(rest);
        Ok(())
    }

    fn tag(&mut self) -> [u8; 16] {
        let (r, s) = self.key.0.split_at(16);
        if self.used != 0 {
            // The unused suffix is zero and used < 16. Append the 1
            // immediately after the last message byte, not after byte 16.
            let (_, suffix) = self.tail.split_at_mut(self.used);
            suffix.fill(0);
            if let Some(marker) = suffix.first_mut() {
                *marker = 1;
            }
            field::absorb(&mut self.acc, r, &self.tail, false);
        }
        field::finish(&self.acc, s)
    }

    /// Finish authentication and return the complete 16-byte tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        self.tag()
    }

    /// Finish verification, comparing all 16 bytes and retiring the key on either outcome.
    pub fn verify(mut self, expected: &[u8; 16]) -> Result<(), Error> {
        let mut computed = self.tag();
        let mut difference = 0;
        for (a, b) in computed.iter().zip(expected) {
            accumulate_secret_byte_difference(&mut difference, a, b);
        }
        let valid = secret_difference_is_zero(&difference).expose_public();
        let _ = clear_owned_region(core::slice::from_mut(&mut difference));
        let _ = clear_owned_region(&mut computed);
        if valid {
            Ok(())
        } else {
            Err(Error::Authentication)
        }
    }
}

impl Drop for Poly1305<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.acc.as_flattened_mut());
        let _ = clear_owned_region(&mut self.tail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_budget_is_nonmutating() {
        let mut key = [0x53; 32];
        let mut mac = OneTimeKey::new(&mut key).start();
        assert_eq!(mac.update(&[7; 31]), Ok(()));
        mac.length = u64::MAX - 1;
        let before = (mac.acc, mac.tail, mac.used, mac.length);
        assert_eq!(mac.update(&[9, 9]), Err(Error::TooLong));
        assert_eq!((mac.acc, mac.tail, mac.used, mac.length), before);
        assert_eq!(mac.update(&[9]), Ok(()));
        assert_eq!(mac.update(&[]), Ok(()));
        assert_eq!(mac.update(&[1]), Err(Error::TooLong));
    }
}
