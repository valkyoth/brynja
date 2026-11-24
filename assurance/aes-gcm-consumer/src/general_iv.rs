//! Frozen independent fixtures, no downstream dependency on an oracle.
use super::{Aes128Gcm, Aes192Gcm, Aes256Gcm, GcmError};

/// Python cryptography 50.0.1: AESGCM(bytes(key_bytes)).encrypt(
/// bytes(range(iv_bytes)), bytes(range(17)), b"header"). Each public vector
/// uses its own key width; ciphertext and full tag are compared separately.
pub fn exercise_general_iv() -> Result<(), GcmError> {
    macro_rules! check {
        ($owner:ident, $width:literal, $storage:literal, $n:literal, $expected:literal) => {{
            let iv: [u8; $n] = core::array::from_fn(|i| i as u8);
            let (prefix, seq) = iv.split_at($n - 4);
            let first = u32::from_be_bytes(seq.try_into().map_err(|_| GcmError::Length)?);
            let mut schedule = [0; $storage];
            let mut sender = $owner::<16, $n>::from_reserved_invocations(
                &[0; $width],
                &mut schedule,
                prefix,
                first,
                1,
            )?;
            let plain: [u8; 17] = core::array::from_fn(|i| i as u8);
            let (mut data, mut scratch) = (plain, [0xff; 17]);
            let (sent, tag) = sender.seal_next_in_place(b"header", &mut data, &mut scratch)?;
            assert_eq!(sent, iv);
            assert_eq!(data, $expected[..17]);
            assert_eq!(tag, $expected[17..]);
            assert_eq!(scratch, [0; 17]);
            drop(sender);
            let receiver = $owner::<16>::for_open(&[0; $width], &mut schedule)?;
            receiver.open_in_place(&iv, b"header", &tag, &mut data, &mut scratch)?;
            assert_eq!(data, plain);
        }};
    }
    check!(Aes128Gcm, 16, 176, 8, b"\x38\x92\xee\xc4\x5b\x0e\x01\xec\x1d\xc7\x88\xd9\xa0\x3e\xcf\xe2\xb5\xbd\xcb\xec\x64\xe7\x2c\x99\x60\x0f\x48\x6b\xa6\x00\x6f\x93\xb7");
    check!(Aes192Gcm, 24, 208, 16, b"\xd8\x3f\x69\x95\x96\x55\xe4\x4d\x5d\x47\x7f\x37\x51\xa7\x4b\xd7\xae\x11\x0e\xec\x4f\xb2\x96\x8f\x9e\x55\x57\xdc\x41\xb4\x84\x82\x85");
    check!(Aes256Gcm, 32, 240, 60, b"\xaa\xa1\x19\x29\x6c\xde\x46\x9a\xfc\x08\x9c\x78\x87\x0a\x77\xf8\x63\xd9\xf2\xea\xe9\x2d\xac\x4d\x25\x6c\xa2\x87\x2e\xee\x35\xd5\x53");
    Ok(())
}
