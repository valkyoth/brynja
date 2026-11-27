#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use brynja_chacha20_parallel_probe::Selected;
use brynja_chacha20_parallel_probe::record;
use brynja_cipher_chacha::{ChaCha20, Error};

#[path = "../../../crates/brynja-crypto/tests/chacha20/appendix.rs"]
mod appendix;

#[test]
fn published_vectors_use_parallel_and_tail_paths() {
    let mut groups = 0;
    for (key, nonce, counter, plain, answer) in appendix::VECTORS {
        let mut data = plain.to_vec();
        record(key, *nonce, counter, &mut data).unwrap();
        groups += data.len() / 256;
        assert_eq!(data, answer);
    }
    assert!(groups > 0);
}

#[test]
fn lanes_carries_every_tail_and_unaligned_buffers() {
    for first in [0, 253, 65533, 0x00ff_fffd, 0x7fff_fffe, u32::MAX - 12] {
        let key = std::array::from_fn(|i| ((i * 37) as u8) ^ first.to_le_bytes()[i % 4]);
        let nonce = std::array::from_fn(|i| key[31 - i]);
        for len in 0..=768 {
            let mut data: Vec<u8> = (0..len + 2).map(|i| (19 * i + len) as u8).collect();
            let mut expected = data.clone();
            ChaCha20::new(&key, nonce, first)
                .apply_keystream_in_place(&mut expected[1..=len])
                .unwrap();
            assert_eq!(record(&key, nonce, first, &mut data[1..=len]), Ok(()));
            assert_eq!(data, expected, "counter {first}, length {len}");
        }
    }
}

#[test]
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn fragmented_public_owners_match_through_the_last_byte() {
    let key = std::array::from_fn(|i| i as u8);
    let nonce = [0x5a; 12];
    let first = u32::MAX - 15;
    let input: Vec<_> = (0..1024).map(|i| (i * 23) as u8).collect();
    let mut expected = input.clone();
    ChaCha20::new(&key, nonce, first)
        .apply_keystream_in_place(&mut expected)
        .unwrap();
    for head in 0..64 {
        for middle in [0, 1, 63, 64, 255, 256, 257, 319, 320, 511, 512, 513] {
            let mut stream = Selected::new(&key, nonce, first);
            let mut out = vec![0xee; 1026];
            out[1..1 + head].copy_from_slice(&input[..head]);
            stream
                .apply_keystream_in_place(&mut out[1..1 + head])
                .unwrap();
            let split = head + middle;
            stream
                .apply_keystream(&input[head..split], &mut out[1 + head..1 + split])
                .unwrap();
            assert_eq!(stream.remaining_bytes(), (1024 - split) as u64);
            // Reject both public layouts before touching bytes or consuming counters.
            let mut oversized = vec![0x77; 1025 - split];
            assert_eq!(
                stream.apply_keystream(&[], &mut oversized),
                Err(Error::LengthMismatch)
            );
            assert_eq!(
                stream.apply_keystream_in_place(&mut oversized),
                Err(Error::Exhausted)
            );
            assert_eq!(
                stream.apply_keystream(&vec![0; oversized.len()], &mut oversized),
                Err(Error::Exhausted)
            );
            assert!(oversized.iter().all(|&v| v == 0x77));
            assert_eq!(stream.remaining_bytes(), (1024 - split) as u64);
            stream
                .apply_keystream(&input[split..], &mut out[1 + split..1025])
                .unwrap();
            assert_eq!(&out[1..1025], expected);
            assert_eq!([out[0], out[1025]], [0xee; 2]);
            assert_eq!(stream.remaining_bytes(), 0);
            assert_eq!(stream.apply_keystream(&[], &mut []), Ok(()));
            assert_eq!(stream.apply_keystream_in_place(&mut []), Ok(()));
        }
    }
}

#[test]
fn final_batch_and_oversized_records_are_atomic() {
    let first = u32::MAX - 3;
    let mut block = [0x5a; 256];
    let mut expected = block;
    for start in first + 1..=u32::MAX {
        assert_eq!(
            record(&[1; 32], [2; 12], start, &mut block),
            Err(Error::Exhausted)
        );
        assert_eq!(block, expected);
    }
    ChaCha20::new(&[1; 32], [2; 12], first)
        .apply_keystream_in_place(&mut expected)
        .unwrap();
    assert_eq!(record(&[1; 32], [2; 12], first, &mut block), Ok(()));
    assert_eq!(block, expected);

    for (counter, size) in [(first, 257), (first - 4, 513), (u32::MAX, 65)] {
        let mut data = vec![0xa5; size];
        assert_eq!(
            record(&[1; 32], [2; 12], counter, &mut data),
            Err(Error::Exhausted)
        );
        assert!(data.iter().all(|&v| v == 0xa5));
    }
}
