//! Portable composition shared by the key owners and the vector tests.
use super::{Frame, HashRoute, InitialCounter, PortableHash, inc32, initial_counter, size};
use crate::aes::{self, Aes128ExpandedKey, Aes192ExpandedKey, Aes256ExpandedKey, SecretBlock};
use brynja_core::clear_owned_region;

type Block = [u8; 16];

#[derive(Debug, Eq, PartialEq)]
enum Error {
    Length,
    Authentication,
    Aes(aes::Error),
    Hash(crate::ghash::Error),
    Invariant,
    Exhausted,
    TagLength,
}

// Private, not a downstream provider contract. GCM uses forward AES only.
trait Forward {
    // Runs inside the staging transaction, after input/nonce admission.
    fn operation<T>(&self, work: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        work()
    }
    fn hash_route(&self) -> &impl HashRoute;
    fn encrypt<'a>(&self, input: &Block, out: &'a mut Block) -> Result<SecretBlock<'a>, Error>;
}

macro_rules! forward {
    ($owner:ident) => {
        impl Forward for $owner<'_> {
            fn hash_route(&self) -> &impl HashRoute {
                &PortableHash
            }
            fn encrypt<'a>(
                &self,
                input: &Block,
                out: &'a mut Block,
            ) -> Result<SecretBlock<'a>, Error> {
                self.encrypt_block(input, out).map_err(Error::Aes)
            }
        }
    };
}
forward!(Aes128ExpandedKey);
forward!(Aes192ExpandedKey);
forward!(Aes256ExpandedKey);

struct ClearingBlock(Block);
impl Drop for ClearingBlock {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}

struct Stage<'a>(&'a mut [u8]);
impl Drop for Stage<'_> {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            let _ = clear_owned_region(self.0);
        }
    }
}

fn as_block(bytes: &[u8]) -> Result<&Block, Error> {
    bytes.try_into().map_err(|_| Error::Invariant)
}

fn admit(iv: &[u8], aad: &[u8], input: &[u8]) -> Result<Frame, Error> {
    if iv.is_empty() || size(iv).map_err(Error::Hash)? > u64::MAX / 8 {
        return Err(Error::Length);
    }
    Frame::message(
        size(aad).map_err(Error::Hash)?,
        size(input).map_err(Error::Hash)?,
    )
    .map_err(Error::Hash)
}

fn with_material<T>(
    key: &impl Forward,
    route: &impl HashRoute,
    iv: &[u8],
    use_material: impl FnOnce(&Block, &Block, &Block) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut h_storage = [0; 16];
    let h = key.encrypt(&[0; 16], &mut h_storage)?;
    let h = as_block(h.expose())?;
    let mut iv_storage = [0; 16];
    let initial = initial_counter(route, h, iv, &mut iv_storage).map_err(Error::Hash)?;
    let j0 = match &initial {
        InitialCounter::FromPublicIv(block) => block,
        InitialCounter::FromSecretHash(secret) => as_block(secret.expose())?,
    };
    let mut mask_storage = [0; 16];
    let mask = key.encrypt(j0, &mut mask_storage)?;
    use_material(h, j0, as_block(mask.expose())?)
}

fn gctr(key: &impl Forward, j0: &Block, input: &[u8], stage: &mut [u8]) -> Result<(), Error> {
    let mut counter = ClearingBlock([0; 16]);
    counter.0.copy_from_slice(j0);
    for (src, dst) in input.chunks(16).zip(stage.chunks_mut(16)) {
        inc32(&mut counter.0);
        let mut stream_storage = [0; 16];
        let stream = key.encrypt(&counter.0, &mut stream_storage)?;
        for ((out, p), k) in dst.iter_mut().zip(src).zip(as_block(stream.expose())?) {
            *out = p ^ k;
        }
    }
    Ok(())
}

fn masked_tag(
    route: &impl HashRoute,
    frame: Frame,
    h: &Block,
    mask: &Block,
    aad: &[u8],
    ciphertext: &[u8],
    tag: &mut Block,
) -> Result<(), Error> {
    let mut s_storage = [0; 16];
    let s = frame
        .hash(route, h, aad, ciphertext, &mut s_storage)
        .map_err(Error::Hash)?;
    for ((out, m), hash) in tag.iter_mut().zip(mask).zip(as_block(s.expose())?) {
        *out = m ^ hash;
    }
    Ok(())
}

mod transaction;
use transaction::Buffers;

impl Buffers<'_> {
    fn frame(&self, iv: &[u8], aad: &[u8], scratch: &[u8]) -> Result<Frame, Error> {
        admit(
            iv,
            aad,
            self.checked_input(scratch.len()).ok_or(Error::Length)?,
        )
    }
}

fn seal_admitted<const T: usize>(
    key: &impl Forward,
    iv: &[u8],
    aad: &[u8],
    io: Buffers<'_>,
    scratch: &mut [u8],
    frame: Frame,
    policy: &policy::TagPolicy<T>,
) -> Result<[u8; T], Error> {
    let stage = Stage(scratch);
    io.transact(stage.0, Error::Length, |input, work| {
        key.operation(|| {
            let route = key.hash_route();
            with_material(key, route, iv, |h, j0, mask| {
                gctr(key, j0, input, work)?;
                // For truncated tags, the undisclosed suffix must not be left behind.
                let mut full = ClearingBlock([0; 16]);
                masked_tag(route, frame, h, mask, aad, work, &mut full.0)?;
                Ok(*policy.prefix(&full.0)?)
            })
        })
    })
}

fn open_with<const T: usize>(
    key: &impl Forward,
    iv: &[u8],
    aad: &[u8],
    io: Buffers<'_>,
    scratch: &mut [u8],
    tag: &[u8; T],
    policy: &policy::TagPolicy<T>,
) -> Result<(), Error> {
    let frame = io.frame(iv, aad, scratch)?;
    let stage = Stage(scratch);
    io.transact(stage.0, Error::Length, |input, work| {
        key.operation(|| {
            let route = key.hash_route();
            with_material(key, route, iv, |h, j0, mask| {
                let mut expected = ClearingBlock([0; 16]);
                masked_tag(route, frame, h, mask, aad, input, &mut expected.0)?;
                let mut difference = 0u8;
                for (a, b) in policy.prefix(&expected.0)?.iter().zip(tag) {
                    brynja_core::accumulate_secret_byte_difference(&mut difference, a, b);
                }
                let ok = brynja_core::secret_difference_is_zero(&difference).expose_public();
                let _ = clear_owned_region(core::slice::from_mut(&mut difference));
                if !ok {
                    return Err(Error::Authentication);
                }
                gctr(key, j0, input, work)
            })
        })
    })
}

mod policy;

#[cfg(any(feature = "aes-gcm-execution", feature = "gmac-execution"))]
mod paired;

#[cfg(feature = "gmac")]
pub mod gmac;

#[cfg(feature = "aes-gcm")]
pub(super) mod api;

#[cfg(test)]
mod tests;
