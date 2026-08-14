//! Canonical ASN.1 value behavior and malformed corpora.

use brynja_pki::{
    Asn1Error, BitString, CanonicalInteger, CanonicalSequence, CanonicalSet, CanonicalSetOf,
    CanonicalValue, CharacterString, CharacterStringKind, DerElement, DerError, DerEvent,
    DerLimitBuildError, DerLimits, GeneralizedTime, IntegerValueError, ObjectIdentifier,
    OctetString, Reader, UtcTime,
};

#[derive(Debug)]
enum TestError {
    Asn1(Asn1Error),
    Der(DerError),
    Limits(DerLimitBuildError),
    Message(&'static str),
}

impl From<Asn1Error> for TestError {
    fn from(error: Asn1Error) -> Self {
        Self::Asn1(error)
    }
}

impl From<DerError> for TestError {
    fn from(error: DerError) -> Self {
        Self::Der(error)
    }
}

impl From<DerLimitBuildError> for TestError {
    fn from(error: DerLimitBuildError) -> Self {
        Self::Limits(error)
    }
}

impl From<&'static str> for TestError {
    fn from(message: &'static str) -> Self {
        Self::Message(message)
    }
}

impl core::fmt::Display for TestError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Asn1(error) => write!(formatter, "ASN.1 failure: {error:?}"),
            Self::Der(error) => write!(formatter, "DER failure: {error:?}"),
            Self::Limits(error) => write!(formatter, "limit failure: {error:?}"),
            Self::Message(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for TestError {}

fn limits() -> Result<DerLimits, DerLimitBuildError> {
    DerLimits::builder()
        .input_bytes(4096)?
        .depth(8)?
        .nodes(64)?
        .children(32)?
        .identifier_octets(10)?
        .length_octets(9)?
        .value_bytes(2048)?
        .work(16_384)?
        .build()
}

fn first<'input>(input: &'input [u8]) -> Result<DerElement<'input>, TestError> {
    let mut reader = Reader::<8>::new(input, limits()?)?;
    match reader.next_event()? {
        Some(DerEvent::Primitive(element) | DerEvent::ConstructedStart(element)) => Ok(element),
        _ => Err("DER element missing".into()),
    }
}

fn expect_asn1_error<T>(
    result: Result<T, Asn1Error>,
    expected: Asn1Error,
) -> Result<(), TestError> {
    match result {
        Err(error) if error == expected => Ok(()),
        Err(_) => Err("unexpected ASN.1 error".into()),
        Ok(_) => Err("malformed ASN.1 value accepted".into()),
    }
}

#[test]
fn canonical_booleans_are_exact() -> Result<(), TestError> {
    for (input, expected) in [(&[1, 1, 0][..], false), (&[1, 1, 0xff][..], true)] {
        assert!(matches!(
            CanonicalValue::decode_primitive(first(input)?)?,
            CanonicalValue::Boolean(value) if value == expected
        ));
    }
    for input in [&[1, 0][..], &[1, 1, 1][..], &[1, 2, 0, 0][..]] {
        expect_asn1_error(
            CanonicalValue::decode_primitive(first(input)?),
            Asn1Error::InvalidBoolean,
        )?;
    }
    Ok(())
}

#[test]
fn integers_are_minimal_and_checked_before_conversion() -> Result<(), TestError> {
    let cases = [
        (&[2, 1, 0][..], 0_i64),
        (&[2, 1, 0x7f][..], 127),
        (&[2, 2, 0, 0x80][..], 128),
        (&[2, 1, 0x80][..], -128),
        (&[2, 2, 0xff, 0x7f][..], -129),
    ];
    for (input, expected) in cases {
        let integer = CanonicalInteger::decode(first(input)?)?;
        assert_eq!(integer.try_i64(), Ok(expected));
        assert_eq!(integer.is_negative(), expected < 0);
    }

    for input in [&[2, 0][..], &[2, 2, 0, 0x7f][..], &[2, 2, 0xff, 0x80][..]] {
        expect_asn1_error(
            CanonicalInteger::decode(first(input)?),
            Asn1Error::InvalidInteger,
        )?;
    }

    let maximum = [2, 9, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let integer = CanonicalInteger::decode(first(&maximum)?)?;
    assert_eq!(integer.try_u64(), Ok(u64::MAX));
    assert_eq!(integer.try_i64(), Err(IntegerValueError::Overflow));
    let negative = CanonicalInteger::decode(first(&[2, 1, 0xff])?)?;
    assert_eq!(negative.try_u64(), Err(IntegerValueError::Negative));
    Ok(())
}

#[test]
fn bit_and_octet_strings_preserve_exact_borrows() -> Result<(), TestError> {
    let empty = BitString::decode(first(&[3, 1, 0])?)?;
    assert_eq!(empty.bit_len(), 0);
    assert!(empty.bytes().is_empty());

    let encoded = [3, 2, 4, 0xa0];
    let bits = BitString::decode(first(&encoded)?)?;
    assert_eq!(bits.unused_bits(), 4);
    assert_eq!(bits.bit_len(), 4);
    assert_eq!(bits.bytes(), encoded.get(3..).ok_or("bit contents")?);

    for input in [
        &[3, 0][..],
        &[3, 1, 1][..],
        &[3, 2, 8, 0][..],
        &[3, 2, 3, 1][..],
    ] {
        expect_asn1_error(
            BitString::decode(first(input)?),
            Asn1Error::InvalidBitString,
        )?;
    }

    let octets = [4, 3, 1, 2, 3];
    assert_eq!(
        OctetString::decode(first(&octets)?)?.as_bytes(),
        octets.get(2..).ok_or("octet contents")?
    );
    assert_eq!(OctetString::decode(first(&[4, 0])?)?.as_bytes(), &[]);
    Ok(())
}

#[test]
fn object_identifiers_are_minimal_terminated_and_bounded() -> Result<(), TestError> {
    let encoded = [6, 6, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d];
    let oid = ObjectIdentifier::decode(first(&encoded)?)?;
    let mut arcs = oid.arcs();
    for expected in [1, 2, 840, 113_549] {
        assert_eq!(arcs.next(), Some(expected));
    }
    assert_eq!(arcs.next(), None);

    for input in [
        &[6, 0][..],
        &[6, 1, 0x80][..],
        &[6, 2, 0x80, 0][..],
        &[6, 1, 0x81][..],
        &[
            6, 11, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ][..],
    ] {
        expect_asn1_error(
            ObjectIdentifier::decode(first(input)?),
            Asn1Error::InvalidObjectIdentifier,
        )?;
    }
    Ok(())
}

#[test]
fn admitted_character_strings_validate_complete_repertoires() -> Result<(), TestError> {
    let cases = [
        (&[12, 2, 0xc3, 0xa5][..], CharacterStringKind::Utf8),
        (
            &[18, 4, b'1', b'2', b' ', b'3'][..],
            CharacterStringKind::Numeric,
        ),
        (
            &[19, 3, b'A', b'+', b'9'][..],
            CharacterStringKind::Printable,
        ),
        (&[22, 2, 0, 0x7f][..], CharacterStringKind::Ia5),
        (&[26, 2, b' ', b'~'][..], CharacterStringKind::Visible),
        (&[28, 4, 0, 1, 0xf6, 0][..], CharacterStringKind::Universal),
        (&[30, 2, 0, 0xe5][..], CharacterStringKind::Bmp),
    ];
    for (input, kind) in cases {
        assert_eq!(CharacterString::decode(first(input)?)?.kind(), kind);
    }

    for input in [
        &[12, 1, 0xff][..],
        &[18, 1, b'A'][..],
        &[19, 1, b'@'][..],
        &[22, 1, 0x80][..],
        &[26, 1, 0x1f][..],
        &[28, 4, 0, 0x11, 0, 0][..],
        &[28, 4, 0, 0, 0xd8, 0][..],
        &[30, 2, 0xd8, 0][..],
        &[30, 1, 0][..],
    ] {
        expect_asn1_error(
            CharacterString::decode(first(input)?),
            Asn1Error::InvalidCharacterString,
        )?;
    }
    expect_asn1_error(
        CharacterString::decode(first(&[20, 1, b'A'])?),
        Asn1Error::UnsupportedType,
    )?;
    Ok(())
}

#[test]
fn utc_and_generalized_times_enforce_calendar_and_der_forms() -> Result<(), TestError> {
    let utc_bytes = b"500101000000Z";
    let mut utc_encoded = [0_u8; 15];
    utc_encoded
        .get_mut(..2)
        .ok_or("UTC header")?
        .copy_from_slice(&[23, 13]);
    utc_encoded
        .get_mut(2..)
        .ok_or("UTC contents")?
        .copy_from_slice(utc_bytes);
    let utc = UtcTime::decode(first(&utc_encoded)?)?;
    assert_eq!(utc.year(), 1950);
    assert_eq!(utc.fields(), (1, 1, 0, 0, 0));

    let generalized = b"\x18\x1220000229010203.25Z";
    let time = GeneralizedTime::decode(first(generalized)?)?;
    assert_eq!(time.year(), 2000);
    assert_eq!(time.fields(), (2, 29, 1, 2, 3));
    assert_eq!(time.fraction(), b"25");

    for contents in [
        &b"4912312359Z"[..],
        &b"491231240000Z"[..],
        &b"490229000000Z"[..],
        &b"491231235960Z"[..],
    ] {
        assert_eq!(decode_utc_contents(contents)?, Err(Asn1Error::InvalidTime));
    }
    for contents in [
        &b"20010229000000Z"[..],
        &b"20000101240000Z"[..],
        &b"20000101000000,1Z"[..],
        &b"20000101000000.0Z"[..],
        &b"20000101000000.10Z"[..],
        &b"20000101000000+0000"[..],
    ] {
        assert_eq!(
            decode_generalized_contents(contents)?,
            Err(Asn1Error::InvalidTime)
        );
    }
    Ok(())
}

#[test]
fn sequence_set_and_set_of_are_distinct_canonical_boundaries() -> Result<(), TestError> {
    let sequence = [0x30, 6, 2, 1, 1, 4, 1, 0xaa];
    let decoded = CanonicalSequence::decode::<8>(first(&sequence)?, limits()?)?;
    assert_eq!(
        decoded.contents(),
        sequence.get(2..).ok_or("sequence contents")?
    );
    assert!(matches!(
        CanonicalValue::from_sequence(decoded),
        CanonicalValue::Sequence(_)
    ));

    let set = [0x31, 6, 2, 1, 1, 4, 1, 0xaa];
    let canonical = CanonicalSet::decode::<8>(first(&set)?, limits()?)?;
    assert_eq!(canonical.contents(), set.get(2..).ok_or("set contents")?);
    let reversed = [0x31, 6, 4, 1, 0xaa, 2, 1, 1];
    expect_asn1_error(
        CanonicalSet::decode::<8>(first(&reversed)?, limits()?),
        Asn1Error::InvalidSetOrder,
    )?;
    let duplicate = [0x31, 6, 2, 1, 1, 2, 1, 2];
    expect_asn1_error(
        CanonicalSet::decode::<8>(first(&duplicate)?, limits()?),
        Asn1Error::InvalidSetOrder,
    )?;
    assert!(CanonicalSetOf::decode::<8>(first(&duplicate)?, limits()?).is_ok());
    let reversed_values = [0x31, 6, 2, 1, 2, 2, 1, 1];
    expect_asn1_error(
        CanonicalSetOf::decode::<8>(first(&reversed_values)?, limits()?),
        Asn1Error::InvalidSetOfOrder,
    )?;

    let malformed_nested = [0x30, 2, 4, 1];
    expect_asn1_error(
        CanonicalSequence::decode::<8>(first(&malformed_nested)?, limits()?),
        Asn1Error::InvalidNestedDer,
    )?;
    Ok(())
}

#[test]
fn tag_class_form_and_unsupported_types_fail_closed() -> Result<(), TestError> {
    expect_asn1_error(
        CanonicalValue::decode_primitive(first(&[0x81, 1, 0])?),
        Asn1Error::NonUniversalTag,
    )?;
    expect_asn1_error(
        CanonicalValue::decode_primitive(first(&[0x21, 0])?),
        Asn1Error::InvalidEncodingForm,
    )?;
    expect_asn1_error(
        CanonicalValue::decode_primitive(first(&[5, 0])?),
        Asn1Error::UnsupportedType,
    )?;
    Ok(())
}

#[test]
fn exhaustive_boolean_bit_padding_and_two_octet_oid_corpora() -> Result<(), TestError> {
    for octet in u8::MIN..=u8::MAX {
        let input = [1, 1, octet];
        let accepted = CanonicalValue::decode_primitive(first(&input)?).is_ok();
        assert_eq!(accepted, matches!(octet, 0 | 0xff));
    }
    for unused in u8::MIN..=u8::MAX {
        for final_octet in u8::MIN..=u8::MAX {
            let input = [3, 2, unused, final_octet];
            let accepted = BitString::decode(first(&input)?).is_ok();
            let expected = if unused <= 7 {
                let mask = (1_u8 << unused).wrapping_sub(1);
                final_octet & mask == 0
            } else {
                false
            };
            assert_eq!(accepted, expected);
        }
    }
    for first_octet in u8::MIN..=u8::MAX {
        for second_octet in u8::MIN..=u8::MAX {
            let input = [6, 2, first_octet, second_octet];
            let accepted = ObjectIdentifier::decode(first(&input)?).is_ok();
            let expected = if first_octet & 0x80 == 0 {
                second_octet & 0x80 == 0 && second_octet != 0x80
            } else {
                first_octet != 0x80 && second_octet & 0x80 == 0
            };
            assert_eq!(accepted, expected);
        }
    }
    Ok(())
}

fn decode_utc_contents(contents: &[u8]) -> Result<Result<(), Asn1Error>, TestError> {
    let mut encoded = [0_u8; 32];
    let length = u8::try_from(contents.len()).map_err(|_| "UTC test length")?;
    let end = contents.len().checked_add(2).ok_or("UTC test overflow")?;
    encoded
        .get_mut(..2)
        .ok_or("UTC header")?
        .copy_from_slice(&[23, length]);
    encoded
        .get_mut(2..end)
        .ok_or("UTC contents")?
        .copy_from_slice(contents);
    let element = first(encoded.get(..end).ok_or("UTC element")?)?;
    Ok(UtcTime::decode(element).map(|_| ()))
}

fn decode_generalized_contents(contents: &[u8]) -> Result<Result<(), Asn1Error>, TestError> {
    let length = u8::try_from(contents.len()).map_err(|_| "generalized time length")?;
    let mut encoded = [0_u8; 64];
    let end = contents
        .len()
        .checked_add(2)
        .ok_or("generalized time overflow")?;
    encoded
        .get_mut(..2)
        .ok_or("generalized time header")?
        .copy_from_slice(&[24, length]);
    encoded
        .get_mut(2..end)
        .ok_or("generalized time contents")?
        .copy_from_slice(contents);
    let element = first(encoded.get(..end).ok_or("generalized time element")?)?;
    Ok(GeneralizedTime::decode(element).map(|_| ()))
}
