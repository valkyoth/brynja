//! Downstream no_std consumer. Compiled against extracted Cargo archives.
#![no_std]
use brynja_crypto::chacha20::{ChaCha20, Error};

/// Exercise disjoint and in-place calls on one stream at the final counter.
pub fn final_block(key: &[u8; 32], nonce: [u8; 12], out: &mut [u8; 64]) -> Result<(), Error> {
    let mut owner = ChaCha20::new(key, nonce, u32::MAX);
    let (head, tail) = out.split_at_mut(1);
    owner.apply_keystream(&[0], head)?;
    tail.fill(0);
    owner.apply_keystream_in_place(tail)?;
    assert_eq!(
        owner.apply_keystream_in_place(&mut [0]),
        Err(Error::Exhausted)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_counter_known_answer() -> Result<(), Error> {
        // Independent one-block OpenSSL enc -chacha20 result for public inputs:
        // IV ffffffff000000000000004a00000000 and the 32 key bytes 00..1f.
        // No linked or runtime OpenSSL dependency.
        let key = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut out = [0xa5; 64];
        final_block(&key, nonce, &mut out)?;
        assert_eq!(
            out,
            [
                0x6d, 0x29, 0xda, 0x5b, 0xd1, 0x6a, 0x47, 0x29, 0x10, 0xe8, 0xc0, 0xbd, 0xb4, 0x7e,
                0xdf, 0xc8, 0x49, 0x9c, 0x32, 0x22, 0xcc, 0x16, 0x8d, 0x37, 0x21, 0x74, 0x7f, 0xc2,
                0xb2, 0x12, 0x66, 0xd9, 0xf1, 0x5c, 0x83, 0x39, 0xf1, 0x0f, 0x35, 0x4d, 0x16, 0xcc,
                0x9b, 0x8e, 0x11, 0x8e, 0xb1, 0x82, 0xbf, 0x85, 0x8c, 0xe5, 0x71, 0x8f, 0xa4, 0xe7,
                0x63, 0x89, 0xea, 0x4e, 0xb5, 0x0a, 0x94, 0x75,
            ]
        );
        Ok(())
    }
}
