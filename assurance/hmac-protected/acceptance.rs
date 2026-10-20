use brynja_crypto_cpu_std::strict_hmac::*;

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
fn compare<A: Algorithm>() -> Result<(), Error> {
    let mut session = Session::<A>::new(TagPolicy::Full, limits())?;
    let key = [0x51; 257];
    let mut expected = vec![0; A::TAG_BYTES];
    let _ = brynja_mac_hmac::Hmac::<A>::authenticate(&key, b"message", &mut expected)
        .map_err(Error::Mac)?;
    let output = session.authenticate(&key, b"message")?;
    assert_eq!(output.bit_len(), A::TAG_BITS);
    assert_eq!(output.expose(), expected);
    let mut public = vec![0; A::TAG_BYTES];
    output.declassify(&mut public, PublicDeclassification::acknowledge())?;
    assert_eq!(public, expected);
    let request = || Request {
        key: &key,
        chunks: &[b"message"],
        tail: Bits::empty(),
    };
    assert!(session.verify(request(), &public, &Cancellation::new())?);
    public[0] ^= 1;
    assert!(!session.verify(request(), &public, &Cancellation::new())?);
    Ok(())
}
#[test]
fn packaged_all_identities() -> Result<(), Error> {
    compare::<Sha224>()?;
    compare::<Sha256>()?;
    compare::<Sha384>()?;
    compare::<Sha512>()?;
    compare::<Sha512_224>()?;
    compare::<Sha512_256>()?;
    compare::<Sha512T<129>>()?;
    compare::<Sha512T<511>>()?;
    compare::<Sha3_224>()?;
    compare::<Sha3_256>()?;
    compare::<Sha3_384>()?;
    compare::<Sha3_512>()?;
    Ok(())
}
#[test]
fn packaged_budgets_and_cancellation() -> Result<(), Error> {
    let mut bound = limits();
    bound.max_key_bytes = 3;
    let mut session = Session::<Sha256>::new(TagPolicy::Bytes(16), bound)?;
    assert!(matches!(
        session.authenticate(b"long", b"message"),
        Err(Error::WorkLimit)
    ));
    let cancel = Cancellation::new();
    cancel.cancel();
    assert!(matches!(
        session.compute(
            Request {
                key: b"key",
                chunks: &[],
                tail: Bits::empty()
            },
            &cancel
        ),
        Err(Error::Cancelled)
    ));
    drop(session.authenticate(b"key", b"message")?);
    Ok(())
}
#[test]
fn packaged_full_partial_tag_has_exact_width() -> Result<(), Error> {
    assert!(Session::<Sha512T<129>>::new(TagPolicy::Bytes(17), limits()).is_err());
    let mut session = Session::<Sha512T<129>>::new(TagPolicy::Full, limits())?;
    let tag = session.authenticate(b"key", b"message")?.expose().to_vec();
    assert_eq!(tag.len(), 17);
    assert_eq!(tag[16] & 127, 0);
    let mut wrong = tag;
    wrong[16] |= 1;
    assert!(!session.verify(
        Request {
            key: b"key",
            chunks: &[b"message"],
            tail: Bits::empty()
        },
        &wrong,
        &Cancellation::new()
    )?);
    Ok(())
}
