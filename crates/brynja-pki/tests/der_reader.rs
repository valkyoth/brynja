//! Bounded DER framing behavior and adversarial limits.

use brynja_pki::{DerError, DerEvent, DerLimitBuildError, DerLimits, Reader, TagClass};

#[derive(Debug)]
enum TestError {
    Der(DerError),
    Limit(DerLimitBuildError),
    Message(&'static str),
}

impl From<DerError> for TestError {
    fn from(error: DerError) -> Self {
        Self::Der(error)
    }
}

impl From<DerLimitBuildError> for TestError {
    fn from(error: DerLimitBuildError) -> Self {
        Self::Limit(error)
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
            Self::Der(error) => write!(formatter, "DER test failure: {error:?}"),
            Self::Limit(error) => write!(formatter, "limit test failure: {error:?}"),
            Self::Message(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for TestError {}

fn limits(
    [
        input,
        depth,
        nodes,
        children,
        identifier,
        length,
        value,
        work,
    ]: [usize; 8],
) -> Result<DerLimits, DerLimitBuildError> {
    DerLimits::builder()
        .input_bytes(input)?
        .depth(depth)?
        .nodes(nodes)?
        .children(children)?
        .identifier_octets(identifier)?
        .length_octets(length)?
        .value_bytes(value)?
        .work(work)?
        .build()
}

fn ordinary() -> Result<DerLimits, DerLimitBuildError> {
    limits([4096, 8, 64, 32, 10, 9, 2048, 16_384])
}

#[test]
fn canonical_primitive_preserves_exact_borrowed_regions() -> Result<(), TestError> {
    let input = [0x04, 0x03, 0xaa, 0xbb, 0xcc];
    let mut reader = Reader::<8>::new(&input, ordinary()?)?;
    let event = reader.next_event()?;
    let Some(DerEvent::Primitive(element)) = event else {
        return Err("primitive event missing".into());
    };
    assert_eq!(element.tag().class(), TagClass::Universal);
    assert!(!element.tag().is_constructed());
    assert_eq!(element.tag().number(), 4);
    assert_eq!(element.depth(), 0);
    assert_eq!(element.header(), &input[..2]);
    assert_eq!(element.contents(), &input[2..]);
    assert_eq!(element.encoded().as_ptr(), input.as_ptr());
    assert!(reader.next_event()?.is_none());
    assert_eq!(reader.nodes(), 1);
    assert_eq!(reader.work(), input.len());
    Ok(())
}

#[test]
fn high_tag_class_and_long_length_are_minimal() -> Result<(), TestError> {
    let mut input = [0_u8; 133];
    input
        .get_mut(0..5)
        .ok_or("header range")?
        .copy_from_slice(&[0x7f, 0x81, 0x00, 0x81, 0x80]);
    let mut reader = Reader::<8>::new(&input, ordinary()?)?;
    let Some(DerEvent::ConstructedStart(element)) = reader.next_event()? else {
        return Err("constructed start missing".into());
    };
    assert_eq!(element.tag().class(), TagClass::Application);
    assert_eq!(element.tag().number(), 128);
    assert_eq!(element.header(), &input[..5]);
    assert_eq!(element.contents().len(), 128);
    assert!(matches!(reader.next_event(), Err(DerError::EndOfContents)));
    Ok(())
}

#[test]
fn nested_constructed_values_emit_balanced_events() -> Result<(), TestError> {
    let input = [0x30, 0x07, 0x30, 0x02, 0x05, 0x00, 0x04, 0x01, 0xaa];
    let mut reader = Reader::<8>::new(&input, ordinary()?)?;
    assert!(
        matches!(reader.next_event()?, Some(DerEvent::ConstructedStart(element)) if element.depth() == 0)
    );
    assert!(
        matches!(reader.next_event()?, Some(DerEvent::ConstructedStart(element)) if element.depth() == 1)
    );
    assert!(
        matches!(reader.next_event()?, Some(DerEvent::Primitive(element)) if element.depth() == 2 && element.tag().number() == 5)
    );
    assert!(matches!(
        reader.next_event()?,
        Some(DerEvent::ConstructedEnd { depth: 1 })
    ));
    assert!(
        matches!(reader.next_event()?, Some(DerEvent::Primitive(element)) if element.depth() == 1 && element.contents() == [0xaa])
    );
    assert!(matches!(
        reader.next_event()?,
        Some(DerEvent::ConstructedEnd { depth: 0 })
    ));
    assert!(reader.next_event()?.is_none());
    assert_eq!(reader.nodes(), 4);
    Ok(())
}

#[test]
fn empty_constructed_and_multiple_roots_are_explicit() -> Result<(), TestError> {
    let input = [0x30, 0x00, 0x05, 0x00];
    let mut reader = Reader::<8>::new(&input, ordinary()?)?;
    assert!(matches!(
        reader.next_event()?,
        Some(DerEvent::ConstructedStart(_))
    ));
    assert!(matches!(
        reader.next_event()?,
        Some(DerEvent::ConstructedEnd { depth: 0 })
    ));
    assert!(matches!(reader.next_event()?, Some(DerEvent::Primitive(_))));
    assert!(reader.next_event()?.is_none());
    Ok(())
}

#[test]
fn every_header_and_value_truncation_is_rejected() -> Result<(), TestError> {
    let complete = [0x04, 0x82, 0x01, 0x00];
    for end in 1..complete.len() {
        let prefix = complete.get(..end).ok_or("prefix")?;
        let mut reader = Reader::<8>::new(prefix, ordinary()?)?;
        assert!(matches!(reader.next_event(), Err(DerError::Truncated)));
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.nodes(), 0);
        assert_eq!(reader.work(), 0);
    }
    let input = [0x04, 0x03, 1, 2];
    let mut reader = Reader::<8>::new(&input, ordinary()?)?;
    assert!(matches!(reader.next_event(), Err(DerError::Truncated)));
    Ok(())
}

#[test]
fn indefinite_and_nonminimal_lengths_are_rejected() -> Result<(), TestError> {
    for (input, expected) in [
        (&[0x04, 0x80][..], DerError::IndefiniteLength),
        (&[0x04, 0x81, 0x7f][..], DerError::NonMinimalLength),
        (&[0x04, 0x82, 0x00, 0x80][..], DerError::NonMinimalLength),
    ] {
        let mut reader = Reader::<8>::new(input, ordinary()?)?;
        assert!(matches!(reader.next_event(), Err(error) if error == expected));
    }
    Ok(())
}

#[test]
fn malformed_and_overflowing_high_tags_are_rejected() -> Result<(), TestError> {
    for (input, expected) in [
        (&[0x1f, 0x00, 0x00][..], DerError::NonMinimalTag),
        (&[0x1f, 0x1e, 0x00][..], DerError::NonMinimalTag),
        (&[0x00, 0x00][..], DerError::EndOfContents),
        (
            &[
                0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00,
            ][..],
            DerError::TagOverflow,
        ),
    ] {
        let mut reader =
            Reader::<12>::new(input, limits([4096, 12, 64, 32, 12, 9, 2048, 16_384])?)?;
        assert!(matches!(reader.next_event(), Err(error) if error == expected));
    }
    Ok(())
}

#[test]
fn child_cannot_cross_constructed_boundary() -> Result<(), TestError> {
    let input = [0x30, 0x02, 0x04, 0x01, 0xaa];
    let mut reader = Reader::<8>::new(&input, ordinary()?)?;
    assert!(matches!(
        reader.next_event()?,
        Some(DerEvent::ConstructedStart(_))
    ));
    assert!(matches!(
        reader.next_event(),
        Err(DerError::BoundaryViolation)
    ));
    assert_eq!(reader.position(), 2);
    assert_eq!(reader.nodes(), 1);
    Ok(())
}

#[test]
fn every_runtime_resource_ceiling_fails_closed() -> Result<(), TestError> {
    let primitive = [0x04, 0x01, 0xaa];
    let cases = [
        (limits([2, 2, 2, 2, 2, 2, 2, 10])?, DerError::InputLimit),
        (limits([3, 2, 0, 2, 2, 2, 2, 10])?, DerError::NodeLimit),
        (limits([3, 2, 2, 0, 2, 2, 2, 10])?, DerError::ChildLimit),
        (limits([3, 2, 2, 2, 2, 2, 0, 10])?, DerError::ValueLimit),
        (limits([3, 2, 2, 2, 2, 2, 2, 2])?, DerError::WorkLimit),
    ];
    for (selected, expected) in cases {
        match Reader::<4>::new(&primitive, selected) {
            Err(error) => assert_eq!(error, expected),
            Ok(mut reader) => {
                assert!(matches!(reader.next_event(), Err(error) if error == expected))
            }
        }
    }

    let mut identifier = Reader::<4>::new(&[0x1f, 0x20, 0x00], limits([3, 2, 2, 2, 1, 2, 2, 10])?)?;
    assert!(matches!(
        identifier.next_event(),
        Err(DerError::IdentifierOctetsLimit)
    ));
    let mut length = Reader::<4>::new(&[0x04, 0x81, 0x80], limits([3, 2, 2, 2, 2, 1, 200, 300])?)?;
    assert!(matches!(
        length.next_event(),
        Err(DerError::LengthOctetsLimit)
    ));
    Ok(())
}

#[test]
fn depth_node_child_and_work_failures_do_not_advance() -> Result<(), TestError> {
    let nested = [0x30, 0x02, 0x30, 0x00];
    let mut depth = Reader::<2>::new(&nested, limits([4, 1, 4, 4, 2, 2, 4, 20])?)?;
    assert!(matches!(
        depth.next_event()?,
        Some(DerEvent::ConstructedStart(_))
    ));
    assert!(matches!(depth.next_event(), Err(DerError::DepthLimit)));
    assert_eq!(depth.position(), 2);
    assert_eq!(depth.nodes(), 1);

    let siblings = [0x05, 0x00, 0x05, 0x00];
    let mut child = Reader::<2>::new(&siblings, limits([4, 1, 4, 1, 2, 2, 4, 20])?)?;
    assert!(matches!(child.next_event()?, Some(DerEvent::Primitive(_))));
    assert!(matches!(child.next_event(), Err(DerError::ChildLimit)));
    assert_eq!(child.position(), 2);
    Ok(())
}

#[test]
fn invalid_stack_and_runtime_depth_are_rejected() -> Result<(), TestError> {
    assert!(matches!(
        Reader::<0>::new(&[], ordinary()?),
        Err(DerError::InvalidLimits)
    ));
    assert!(matches!(
        Reader::<2>::new(&[], limits([0, 3, 1, 1, 1, 1, 1, 1])?),
        Err(DerError::InvalidLimits)
    ));
    assert!(matches!(
        Reader::<2>::new(&[], limits([0, 0, 1, 1, 1, 1, 1, 1])?),
        Err(DerError::InvalidLimits)
    ));
    Ok(())
}

#[test]
fn named_limit_builder_rejects_duplicates_and_omissions() -> Result<(), TestError> {
    let duplicate = DerLimits::builder().input_bytes(1)?.input_bytes(2);
    assert!(matches!(duplicate, Err(DerLimitBuildError::Duplicate(_))));
    let incomplete = DerLimits::builder().input_bytes(1)?.build();
    assert!(matches!(incomplete, Err(DerLimitBuildError::Incomplete(_))));
    Ok(())
}

#[test]
fn every_two_octet_input_is_bounded_and_deterministic() -> Result<(), TestError> {
    let selected = limits([2, 2, 2, 2, 2, 2, 2, 4])?;
    for first in u8::MIN..=u8::MAX {
        for second in u8::MIN..=u8::MAX {
            let input = [first, second];
            let mut left = Reader::<2>::new(&input, selected)?;
            let mut right = Reader::<2>::new(&input, selected)?;
            let left_result = left.next_event();
            let right_result = right.next_event();
            assert_eq!(left_result.is_ok(), right_result.is_ok());
            assert_eq!(left.position(), right.position());
            assert_eq!(left.nodes(), right.nodes());
            assert_eq!(left.work(), right.work());
        }
    }
    Ok(())
}
