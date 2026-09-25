use crate::sha2::{Algorithm, Error, Limits, Session};

#[test]
fn constructors_never_replace_protected_storage_with_ordinary_storage() -> Result<(), Error> {
    let result = Session::new(
        Algorithm::Sha256,
        Limits {
            stack_bytes: 262144,
            max_stack_mapping_bytes: 1048576,
            max_output_mapping_bytes: 65536,
            max_message_bits: 8192,
            max_chunks: 16,
        },
    );
    #[cfg(all(
        not(any(miri, kani)),
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    {
        let mut session = result?;
        for _ in 0..2 {
            let output = session.hash(b"abc")?;
            assert_eq!(
                output.expose(),
                &[
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                    0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                    0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
                ]
            );
        }
    }
    #[cfg(not(all(
        not(any(miri, kani)),
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )))]
    assert!(matches!(result, Err(Error::Resource(_))));
    Ok(())
}
