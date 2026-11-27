//! Portable detached AES-GCM for byte-oriented messages. No allocation, CPU
//! dispatch or public raw AES/GHASH interface is needed.
//!
//! A sender must be given a **durably reserved**, disjoint interval.
//! Use `from_reserved_range` for a key dedicated to 96-bit deterministic IVs.
//! For other or mixed lengths use `from_reserved_invocations` and distribute
//! at most 2^32 invocation numbers **in total for the key**, across prefixes,
//! IV lengths, processes and devices. If earlier key use is uncertain, start
//! this profile with a fresh key. Neither constructor permits selecting the
//! IV on individual seal calls.
//! Persist the reservation before sealing; discard unused IVs after a crash.
//! Coordinate every sender through one reservation policy per raw key. If
//! reservation history is lost, rotate the key. Opening checks the owner's
//! exact IV width (default 12 bytes); it does not detect replay. Use one tag
//! length per raw key (12–16 bytes; default 16), including across reimports.
//! Choose IV widths from a protocol profile, not packet lengths: each owner
//! stores an IV-sized array. Bound untrusted AAD and payloads before allocating
//! buffers or starting linear-time authentication.
//!
//! Each operation takes scratch exactly as long as the message. Once admitted,
//! scratch is cleared on return or unwind. Failed operations leave the destination
//! unchanged. Successfully opened plaintext, the original key, and their copies
//! remain the caller's responsibility. Dropping the owner clears its borrowed
//! schedule, not registers, spills, or memory after abort. No timing qualification.
#![cfg_attr(
    feature = "aes-gcm",
    doc = r#"
For example, pass the provisioned key and an application-reserved range into
the sender. Store or transmit the returned IV and detached tag with the ciphertext.

```
use brynja_crypto::aes_gcm::{Aes256Gcm, GcmError};
fn seal_one(key: &[u8; 32], prefix: [u8; 4], reserved_number: u64,
            message: &mut [u8], scratch: &mut [u8]) -> Result<([u8; 12], [u8; 16]), GcmError> {
    let mut schedule = [0; 240];
    let mut sender = Aes256Gcm::<16>::from_reserved_range(
        key, &mut schedule, prefix, reserved_number, 1)?;
    sender.seal_next_in_place(b"record-v1", message, scratch)
}
```

For a protocol with 16-byte IVs, the third type parameter selects the length.
The 12-byte prefix identifies the context; the last four bytes carry the
globally reserved invocation number. Normal 12-byte senders need no API change.

```
use brynja_crypto::aes_gcm::{Aes256Gcm, GcmError};
fn seal_general(key: &[u8; 32], context: [u8; 12], reserved_number: u32,
                message: &mut [u8], scratch: &mut [u8]) -> Result<([u8; 16], [u8; 16]), GcmError> {
    let mut schedule = [0; 240];
    let mut sender = Aes256Gcm::<16, 16>::from_reserved_invocations(
        key, &mut schedule, &context, reserved_number, 1)?;
    sender.seal_next_in_place(b"record-v1", message, scratch)
}
```
"#
)]
#![forbid(unsafe_code)]

use crate::ghash::{Error, Ghash, SecretHash};

// §5.2.1.1: at most 2^39 - 256 bits, i.e. 2^32 - 2 counter blocks.
const MAX_TEXT_BYTES: u64 = (1u64 << 36) - 32;

struct Frame {
    left_bits: u64,
    right_bits: u64,
    budget: u64,
}

// One selection supplies both IV hashing and message hashing. The caller
// cannot inject an implementation through a public GCM or GMAC constructor.
trait HashRoute {
    #[cfg(test)]
    fn after_product(&self) -> Result<(), Error> {
        Ok(())
    }

    fn start<'a>(
        &'a self,
        h: &'a [u8; 16],
        workspace: &'a mut [u8; 16],
        budget: u64,
    ) -> Result<Ghash<'a>, Error>;
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
std::thread_local! { static TEST_STARTS: core::cell::Cell<usize> = const {core::cell::Cell::new(0)}; }
struct PortableHash;

impl HashRoute for PortableHash {
    fn start<'a>(
        &self,
        h: &'a [u8; 16],
        workspace: &'a mut [u8; 16],
        budget: u64,
    ) -> Result<Ghash<'a>, Error> {
        let frame = Ghash::new(h, workspace, budget);
        #[cfg(test)]
        TEST_STARTS.set(TEST_STARTS.get().saturating_add(1));
        Ok(frame)
    }
}

fn pad(bytes: u64) -> u64 {
    bytes.wrapping_neg() & 15
}

impl Frame {
    fn lengths(left: u64, right: u64) -> Result<Self, Error> {
        let left_bits = left.checked_mul(8).ok_or(Error::LimitExceeded)?;
        let right_bits = right.checked_mul(8).ok_or(Error::LimitExceeded)?;
        // Both byte lengths now fit in 61 bits, even before rounding.
        let budget = [pad(left), right, pad(right), 16]
            .into_iter()
            .try_fold(left, u64::checked_add)
            .ok_or(Error::LimitExceeded)?;
        Ok(Self {
            left_bits,
            right_bits,
            budget,
        })
    }

    fn message(aad: u64, text: u64) -> Result<Self, Error> {
        if text > MAX_TEXT_BYTES {
            return Err(Error::LimitExceeded);
        }
        Self::lengths(aad, text)
    }

    fn hash<'a>(
        self,
        route: &impl HashRoute,
        h: &[u8; 16],
        left: &[u8],
        right: &[u8],
        out: &'a mut [u8; 16],
    ) -> Result<SecretHash<'a>, Error> {
        let mut workspace = [0; 16];
        let mut hash = route.start(h, &mut workspace, self.budget)?;
        #[cfg(not(test))]
        let mut update = |bytes: &[u8]| hash.update(bytes);
        // In composition tests, stop immediately after a completed product.
        // The primitive independently tests interruptions inside its update guard.
        #[cfg(test)]
        let mut used = 0usize;
        #[cfg(test)]
        let mut update = |mut bytes: &[u8]| -> Result<(), Error> {
            while !bytes.is_empty() {
                let room = 16usize.checked_sub(used).ok_or(Error::LimitExceeded)?;
                let (part, rest) = bytes.split_at(bytes.len().min(room));
                hash.update(part)?;
                used = used.checked_add(part.len()).ok_or(Error::LimitExceeded)?;
                if used == 16 {
                    used = 0;
                    route.after_product()?;
                }
                bytes = rest;
            }
            Ok(())
        };
        for bytes in [left, right] {
            update(bytes)?;
            let padding = bytes.len().wrapping_neg() & 15;
            update([0; 16].get(..padding).ok_or(Error::LimitExceeded)?)?;
        }
        update(&self.left_bits.to_be_bytes())?;
        update(&self.right_bits.to_be_bytes())?;
        hash.finish(out)
    }
}

fn size(bytes: &[u8]) -> Result<u64, Error> {
    u64::try_from(bytes.len()).map_err(|_| Error::LimitExceeded)
}

#[cfg(test)]
fn auth_hash<'a>(
    h: &[u8; 16],
    aad: &[u8],
    ciphertext: &[u8],
    out: &'a mut [u8; 16],
) -> Result<SecretHash<'a>, Error> {
    Frame::message(size(aad)?, size(ciphertext)?)?.hash(&PortableHash, h, aad, ciphertext, out)
}

enum InitialCounter<'a> {
    FromPublicIv([u8; 16]),
    FromSecretHash(SecretHash<'a>),
}

fn initial_counter<'a>(
    route: &impl HashRoute,
    h: &[u8; 16],
    iv: &[u8],
    out: &'a mut [u8; 16],
) -> Result<InitialCounter<'a>, Error> {
    match iv.len() {
        0 => Err(Error::LimitExceeded),
        12 => {
            let mut j0 = [0; 16];
            j0[..12].copy_from_slice(iv);
            j0[15] = 1;
            Ok(InitialCounter::FromPublicIv(j0))
        }
        _ => {
            // §7.1: IV || pad || 0^64 || [len(IV)]_64.
            let hash = Frame::lengths(0, size(iv)?)?.hash(route, h, &[], iv, out)?;
            Ok(InitialCounter::FromSecretHash(hash))
        }
    }
}

// §6.2: carry is confined to the low word even for a GHASH-derived J0.
// Per-message counter exhaustion is controlled by the independent text limit.
fn inc32(counter: &mut [u8; 16]) {
    let [.., a, b, c, d] = counter;
    let word = u32::from_be_bytes([*a, *b, *c, *d]);
    [*a, *b, *c, *d] = word.wrapping_add(1).to_be_bytes();
}

#[cfg(all(test, any(feature = "aes-gcm-execution", feature = "gmac-execution")))]
pub(crate) mod interruptions;
#[cfg(test)]
mod tests;

#[cfg(any(feature = "aes-gcm", feature = "gmac", feature = "hazmat-aes-block"))]
pub(crate) mod portable;

#[cfg(feature = "aes-gcm-execution")]
pub use portable::api::execution;
#[cfg(feature = "aes-gcm")]
pub use portable::api::{Aes128Gcm, Aes192Gcm, Aes256Gcm, GcmError};
