//! Diagnostic metadata import only; no public export of a secret or private slice.
use super::{Placed, within};

unsafe extern "C" {
    fn PublicCrossCopy(destination: *mut u8) -> i32;
}

fn decode(bytes: &[u8; 32]) -> [u64; 4] {
    let mut token = [0; 4];
    for (word, chunk) in token.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut value = [0; 8];
        value.copy_from_slice(chunk);
        *word = u64::from_le_bytes(value);
    }
    token
}

pub(super) fn rehash(
    owner: &mut Placed<'_>,
    epoch: u64,
    low: usize,
    high: usize,
) -> (usize, Option<[u64; 4]>) {
    let mut bytes = [0_u8; 32];
    if !within(bytes.as_ptr().addr(), bytes.len(), low, high) {
        owner.quarantine();
        return (190, None);
    }
    // SAFETY: exclusive initialized fixed array is in the admitted worker;
    // C copies exactly 32 bytes with the OS primitive, never a host dereference.
    let copied = unsafe { PublicCrossCopy(bytes.as_mut_ptr()) == 0 };
    let token = decode(&bytes);
    let _ = brynja_core::clear_owned_region(&mut bytes);
    if !copied {
        owner.quarantine();
        return (121, None);
    }
    super::retained_rehash_worker::rehash(owner, token, epoch, low, high)
}

#[cfg(test)]
mod tests {
    #[unsafe(no_mangle)]
    extern "C" fn PublicCrossCopy(_: *mut u8) -> i32 {
        -1
    }

    #[test]
    fn every_token_word_preserves_little_endian_identity_and_generation() {
        let words = [0x0123456789abcdef_u64, 0xfedcba9876543210, u64::MAX, 1];
        let mut bytes = [0; 32];
        for (chunk, word) in bytes.chunks_exact_mut(8).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(super::decode(&bytes), words);
        assert_eq!(super::decode(&[0; 32]), [0; 4]);
    }
}
