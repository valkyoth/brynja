//! Replay public OpenSSL answers against the extracted crate, not the checkout.
use brynja_crypto::chacha20::ChaCha20;

fn take<'a>(input: &mut &'a [u8], size: usize) -> &'a [u8] {
    input.split_off(..size).expect("truncated oracle record")
}

pub fn replay(mut corpus: &[u8]) -> Result<usize, &'static str> {
    let mut count = 0;
    while !corpus.is_empty() {
        let counter = u32::from_le_bytes(take(&mut corpus, 4).try_into().unwrap());
        let len = usize::from(u16::from_le_bytes(take(&mut corpus, 2).try_into().unwrap()));
        let key = take(&mut corpus, 32).try_into().unwrap();
        let nonce = take(&mut corpus, 12).try_into().unwrap();
        let plain = take(&mut corpus, len);
        let cipher = take(&mut corpus, len);
        let mut seal = ChaCha20::new(key, nonce, counter);
        let mut out = vec![0xa5; len];
        seal.apply_keystream(plain, &mut out)
            .map_err(|_| "unexpected rejection")?;
        if out != cipher {
            return Err("ciphertext differs");
        }
        let mut open = ChaCha20::new(key, nonce, counter);
        let mut recovered = cipher.to_vec();
        let stride = [1, 31, 63, 64, 65, 127, 256][count % 7];
        for part in recovered.chunks_mut(stride) {
            open.apply_keystream_in_place(part)
                .map_err(|_| "fragment rejected")?;
        }
        let left = ((1u64 << 32) - u64::from(counter)) * 64 - len as u64;
        if recovered != plain || seal.remaining_bytes() != left || open.remaining_bytes() != left {
            return Err("plaintext or remaining budget differs");
        }
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
const CORPUS: &[u8] = include_bytes!("public-corpus.bin");

#[test]
fn independent_known_answers() {
    assert_eq!(replay(CORPUS), Ok(302));
}

#[test]
fn rejects_altered_expected_ciphertext() {
    let mut corrupted = CORPUS.to_vec();
    *corrupted.last_mut().unwrap() ^= 1; // final byte of the last expected output
    assert_eq!(replay(&corrupted), Err("ciphertext differs"));
}
