use crate::hmac::*;

fn limits() -> Limits {
    Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 65536,
        max_key_bytes: 4096,
        max_message_bits: 65536,
        max_chunks: 16,
    }
}

#[test]
fn invalid_resources_and_policies_reject() {
    let mut invalid = limits();
    invalid.stack_bytes = 0;
    assert!(matches!(
        Session::<Sha256>::new(TagPolicy::Full, invalid),
        Err(Error::Resource(_))
    ));
    assert!(matches!(
        Session::<Sha256>::new(TagPolicy::Bytes(15), limits()),
        Err(Error::InvalidTagPolicy)
    ));
    assert!(matches!(
        Session::<Sha512T<129>>::new(TagPolicy::Bytes(17), limits()),
        Err(Error::InvalidTagPolicy)
    ));
    assert!(Session::<Sha512T<127>>::new(TagPolicy::Full, limits()).is_err());
    assert!(Session::<Sha512T<384>>::new(TagPolicy::Full, limits()).is_err());
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
#[test]
fn unsupported_platform_rejects_every_identity_without_fallback() {
    macro_rules! reject {
        ($($identity:ty),+ $(,)?) => { $(
            assert!(matches!(Session::<$identity>::new(TagPolicy::Full, limits()),
                             Err(Error::Resource(_))));
        )+ };
    }
    reject!(
        Sha224,
        Sha256,
        Sha384,
        Sha512,
        Sha512_224,
        Sha512_256,
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
        Sha512T<129>,
        Sha512T<511>
    );
}

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
mod native {
    use super::*;

    // RFC 4231 test case 1: fixed public test key/message, not application secrets.
    const EXPECTED: [u8; 32] = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
        0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
        0xcf, 0xf7,
    ];
    const KEY: [u8; 20] = [0x0b; 20];

    fn request() -> Request<'static> {
        Request {
            key: &KEY,
            chunks: &[b"Hi ", b"There"],
            tail: Bits::empty(),
        }
    }

    #[test]
    fn rfc4231_reuse_verification_and_explicit_release() -> Result<(), Error> {
        let mut session = Session::<Sha256>::new(TagPolicy::Full, limits())?;
        for _ in 0..2 {
            let output = session.compute(request(), &Cancellation::new())?;
            assert_eq!(output.bit_len(), 256);
            assert_eq!(output.expose(), EXPECTED);
            let mut public = [0; 32];
            output.declassify(&mut public, PublicDeclassification::acknowledge())?;
            assert_eq!(public, EXPECTED);
            assert_eq!(
                session.verify(request(), &public, &Cancellation::new()),
                Ok(())
            );
            public[0] ^= 1;
            assert_eq!(
                session.verify(request(), &public, &Cancellation::new()),
                Err(Error::Mismatch)
            );
        }
        Ok(())
    }

    #[test]
    fn request_errors_preserve_reuse_and_public_destination() -> Result<(), Error> {
        let mut session = Session::<Sha256>::new(TagPolicy::Bytes(16), limits())?;
        let mut public = [0xa5; 15];
        let output = session.compute(request(), &Cancellation::new())?;
        assert!(matches!(
            output.declassify(&mut public, PublicDeclassification::acknowledge()),
            Err(Error::OutputLength)
        ));
        assert_eq!(public, [0xa5; 15]);
        let cancel = Cancellation::new();
        cancel.cancel();
        assert!(matches!(
            session.compute(request(), &cancel),
            Err(Error::Cancelled)
        ));
        assert!(matches!(
            session.verify(request(), &EXPECTED, &Cancellation::new()),
            Err(Error::OutputLength)
        ));
        assert_eq!(
            session.compute(request(), &Cancellation::new())?.expose(),
            &EXPECTED[..16]
        );
        // Forgetting an output cannot prevent subsequent session use and clearing.
        core::mem::forget(session.compute(request(), &Cancellation::new())?);
        assert_eq!(
            session.authenticate(&KEY, b"Hi There")?.expose(),
            &EXPECTED[..16]
        );
        Ok(())
    }

    #[test]
    fn every_named_identity_and_general_partial_tag_round_trip() -> Result<(), Error> {
        macro_rules! check {
            ($identity:ty, $bits:literal, $bytes:literal) => {{
                let mut session = Session::<$identity>::new(TagPolicy::Full, limits())?;
                let output = session.compute(request(), &Cancellation::new())?;
                assert_eq!(output.bit_len(), $bits);
                let mut public = [0; $bytes];
                output.declassify(&mut public, PublicDeclassification::acknowledge())?;
                assert_eq!(
                    session.verify(request(), &public, &Cancellation::new()),
                    Ok(())
                );
                public[0] ^= 1;
                assert_eq!(
                    session.verify(request(), &public, &Cancellation::new()),
                    Err(Error::Mismatch)
                );
            }};
        }
        check!(Sha224, 224, 28);
        check!(Sha256, 256, 32);
        check!(Sha384, 384, 48);
        check!(Sha512, 512, 64);
        check!(Sha512_224, 224, 28);
        check!(Sha512_256, 256, 32);
        check!(Sha3_224, 224, 28);
        check!(Sha3_256, 256, 32);
        check!(Sha3_384, 384, 48);
        check!(Sha3_512, 512, 64);
        check!(Sha512T<129>, 129, 17);
        check!(Sha512T<511>, 511, 64);
        let mut partial = Session::<Sha512T<129>>::new(TagPolicy::Full, limits())?;
        let mut public = [0; 17];
        partial
            .compute(request(), &Cancellation::new())?
            .declassify(&mut public, PublicDeclassification::acknowledge())?;
        assert_eq!(public[16] & 127, 0);
        public[16] |= 1;
        assert_eq!(
            partial.verify(request(), &public, &Cancellation::new()),
            Err(Error::Mismatch)
        );
        Ok(())
    }
}
