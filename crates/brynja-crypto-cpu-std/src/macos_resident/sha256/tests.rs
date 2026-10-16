use super::*;

fn limits() -> Limits {
    Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_output_mapping_bytes: 65536,
        max_message_bytes: 8192,
        max_chunks: 16,
    }
}
#[test]
fn rejects_invalid_configuration() {
    let mut l = limits();
    l.max_chunks = 0;
    assert!(matches!(Sha256Session::new(l), Err(Error::InvalidSize)));
    l = limits();
    l.stack_bytes = 65535;
    assert!(matches!(Sha256Session::new(l), Err(Error::InvalidSize)));
}
#[test]
fn request_bounds_reject_even_empty_chunk_abuse() {
    let mut l = limits();
    l.max_message_bytes = 0;
    assert_eq!(validate(l, &[b"a"]), Err(Error::WorkLimit));
    assert_eq!(validate(l, &[b""]), Ok(()));
    assert_eq!(validate(l, &[b"".as_slice(); 17]), Err(Error::WorkLimit));
}
#[cfg(not(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani)))))]
#[test]
fn other_targets_never_fall_back() {
    assert!(matches!(
        Sha256Session::new(limits()),
        Err(Error::Unsupported)
    ));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani))))]
mod native {
    use super::*;
    #[test]
    fn post_write_error_clears_both_resources_and_allows_reuse() -> Result<(), Error> {
        let mut session = Sha256Session::new(limits())?;
        session.fault = 1;
        assert!(matches!(session.hash(b"abc"), Err(Error::Invariant)));
        assert!(session.output.bytes().iter().all(|b| *b == 0));
        assert!(session.stack.bytes().iter().all(|b| *b == 0));
        session.fault = 0;
        assert!(session.hash(b"abc").is_ok());
        Ok(())
    }
    #[test]
    #[cfg(panic = "unwind")]
    fn post_write_unwind_clears_both_resources_and_allows_reuse() -> Result<(), Error> {
        let mut session = Sha256Session::new(limits())?;
        session.fault = 2;
        assert!(matches!(session.hash(b"abc"), Err(Error::WorkerPanicked)));
        assert!(session.output.bytes().iter().all(|b| *b == 0));
        assert!(session.stack.bytes().iter().all(|b| *b == 0));
        session.fault = 0;
        assert!(session.hash(b"abc").is_ok());
        Ok(())
    }
    #[test]
    fn known_answer_and_differential_boundaries() -> Result<(), Error> {
        let mut session = Sha256Session::new(limits())?;
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(session.hash(b"abc")?.expose(), expected);
        for len in [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 4096, 8192] {
            let message = vec![0x5a; len];
            let mut reference = brynja_hash_sha2::Sha256::new();
            reference.update(&message).map_err(|_| Error::Invariant)?;
            let expected = reference.finalize();
            let chunks: Vec<&[u8]> = message.chunks(1024).collect();
            assert_eq!(session.hash_chunks(&chunks)?.expose(), expected.as_bytes());
            assert!(session.output.bytes().iter().all(|b| *b == 0));
        }
        Ok(())
    }
    #[test]
    fn forgotten_loan_and_rejection_clear_and_allow_reuse() -> Result<(), Error> {
        let mut session = Sha256Session::new(limits())?;
        core::mem::forget(session.hash(b"abc")?);
        assert!(session.output.bytes().iter().any(|b| *b != 0));
        assert!(matches!(
            session.hash_chunks(&[b"".as_slice(); 17]),
            Err(Error::WorkLimit)
        ));
        assert!(session.output.bytes().iter().all(|b| *b == 0));
        assert!(session.hash(b"abc").is_ok());
        Ok(())
    }
    #[cfg(feature = "strict-sha2")]
    #[test]
    fn strict_profile_still_rejects_mac() {
        use crate::{protected_memory, strict_sha2};
        assert!(matches!(
            strict_sha2::Session::new(
                strict_sha2::Algorithm::Sha256,
                strict_sha2::Limits {
                    stack_bytes: 262144,
                    max_stack_mapping_bytes: 1048576,
                    max_output_mapping_bytes: 65536,
                    max_message_bits: 65536,
                    max_chunks: 16
                }
            ),
            Err(strict_sha2::Error::Resource(
                protected_memory::Error::Unsupported
            ))
        ));
    }
}
