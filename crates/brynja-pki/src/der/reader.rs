//! Iterative caller-bounded DER traversal.

use super::{DerError, DerLimits, Tag, TagClass};

#[derive(Clone, Copy)]
struct Frame {
    end: usize,
    children: usize,
}

impl Frame {
    const EMPTY: Self = Self {
        end: 0,
        children: 0,
    };
}

/// One borrowed canonical DER identifier-length-value envelope.
///
/// Contents and complete encoding alias the caller's input. This type omits
/// `Debug` and `Display` so hostile or sensitive bytes are not formatted.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DerElement<'input> {
    tag: Tag,
    depth: usize,
    header: &'input [u8],
    contents: &'input [u8],
    encoded: &'input [u8],
}

impl<'input> DerElement<'input> {
    /// Returns the canonical decoded tag.
    #[must_use]
    pub const fn tag(&self) -> Tag {
        self.tag
    }
    /// Returns the zero-based nesting depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }
    /// Borrows the exact identifier and length octets.
    #[must_use]
    pub const fn header(&self) -> &'input [u8] {
        self.header
    }
    /// Borrows the exact contents octets.
    #[must_use]
    pub const fn contents(&self) -> &'input [u8] {
        self.contents
    }
    /// Borrows the complete exact encoding.
    #[must_use]
    pub const fn encoded(&self) -> &'input [u8] {
        self.encoded
    }
}

/// One event from a non-recursive depth-first DER traversal.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum DerEvent<'input> {
    /// A primitive value whose contents have been skipped transactionally.
    Primitive(DerElement<'input>),
    /// A constructed value whose children follow in subsequent events.
    ConstructedStart(DerElement<'input>),
    /// The exact end of one constructed value.
    ConstructedEnd {
        /// The zero-based depth of the constructed value that ended.
        depth: usize,
    },
}

/// Allocation-free, non-recursive DER framing reader.
///
/// `STACK` is the compile-time maximum number of simultaneously open
/// constructed values. Runtime [`DerLimits`] may select a lower depth. Any
/// failed call leaves position, depth, node, child, and work accounting
/// unchanged.
///
/// ```compile_fail
/// let bytes = [0x05, 0x00];
/// let limits: brynja_pki::DerLimits = todo!();
/// let reader = brynja_pki::Reader::<4>::new(&bytes, limits).unwrap();
/// println!("{reader:?}");
/// ```
pub struct Reader<'input, const STACK: usize> {
    input: &'input [u8],
    limits: DerLimits,
    frames: [Frame; STACK],
    position: usize,
    depth: usize,
    nodes: usize,
    root_children: usize,
    work: usize,
}

impl<'input, const STACK: usize> Reader<'input, STACK> {
    /// Creates a reader after checking complete-input and stack limits.
    pub fn new(input: &'input [u8], limits: DerLimits) -> Result<Self, DerError> {
        if STACK == 0
            || limits.depth() == 0
            || limits.depth() > STACK
            || limits.identifier_octets() == 0
            || limits.length_octets() == 0
            || input.len() > limits.input_bytes()
        {
            return Err(if input.len() > limits.input_bytes() {
                DerError::InputLimit
            } else {
                DerError::InvalidLimits
            });
        }
        Ok(Self {
            input,
            limits,
            frames: [Frame::EMPTY; STACK],
            position: 0,
            depth: 0,
            nodes: 0,
            root_children: 0,
            work: 0,
        })
    }

    /// Returns the next depth-first event, or `None` at the exact input end.
    pub fn next_event(&mut self) -> Result<Option<DerEvent<'input>>, DerError> {
        if self.depth > 0 {
            let frame = self.frame(self.parent_index()?)?;
            if self.position == frame.end {
                self.depth = self.depth.saturating_sub(1);
                return Ok(Some(DerEvent::ConstructedEnd { depth: self.depth }));
            }
            if self.position > frame.end {
                return Err(DerError::BoundaryViolation);
            }
        } else if self.position == self.input.len() {
            return Ok(None);
        }

        let start = self.position;
        let boundary = if self.depth == 0 {
            self.input.len()
        } else {
            self.frame(self.parent_index()?)?.end
        };
        let (tag, after_tag) = parse_tag(self.input, start, self.limits.identifier_octets())?;
        let (length, content_start) =
            parse_length(self.input, after_tag, self.limits.length_octets())?;
        if length > self.limits.value_bytes() {
            return Err(DerError::ValueLimit);
        }
        let end = content_start
            .checked_add(length)
            .ok_or(DerError::LengthOverflow)?;
        if end > self.input.len() {
            return Err(DerError::Truncated);
        }
        if end > boundary {
            return Err(DerError::BoundaryViolation);
        }

        let next_nodes = self.nodes.checked_add(1).ok_or(DerError::NodeLimit)?;
        if next_nodes > self.limits.nodes() {
            return Err(DerError::NodeLimit);
        }
        let encoded_len = end.checked_sub(start).ok_or(DerError::LengthOverflow)?;
        let next_work = self
            .work
            .checked_add(encoded_len)
            .ok_or(DerError::WorkLimit)?;
        if next_work > self.limits.work() {
            return Err(DerError::WorkLimit);
        }
        let parent_children = self.current_children()?;
        let next_children = parent_children.checked_add(1).ok_or(DerError::ChildLimit)?;
        if next_children > self.limits.children() {
            return Err(DerError::ChildLimit);
        }
        if tag.is_constructed() && self.depth >= self.limits.depth() {
            return Err(DerError::DepthLimit);
        }

        let header = self
            .input
            .get(start..content_start)
            .ok_or(DerError::Truncated)?;
        let contents = self
            .input
            .get(content_start..end)
            .ok_or(DerError::Truncated)?;
        let encoded = self.input.get(start..end).ok_or(DerError::Truncated)?;
        let element = DerElement {
            tag,
            depth: self.depth,
            header,
            contents,
            encoded,
        };

        self.set_current_children(next_children)?;
        self.nodes = next_nodes;
        self.work = next_work;
        if tag.is_constructed() {
            match self.frames.get_mut(self.depth) {
                Some(slot) => *slot = Frame { end, children: 0 },
                None => return Err(DerError::DepthLimit),
            }
            self.depth = self.depth.checked_add(1).ok_or(DerError::DepthLimit)?;
            self.position = content_start;
            Ok(Some(DerEvent::ConstructedStart(element)))
        } else {
            self.position = end;
            Ok(Some(DerEvent::Primitive(element)))
        }
    }

    /// Returns successful value count.
    #[must_use]
    pub const fn nodes(&self) -> usize {
        self.nodes
    }
    /// Returns charged deterministic work.
    #[must_use]
    pub const fn work(&self) -> usize {
        self.work
    }
    /// Returns the current input offset.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    fn frame(&self, index: usize) -> Result<Frame, DerError> {
        self.frames.get(index).copied().ok_or(DerError::DepthLimit)
    }
    fn current_children(&self) -> Result<usize, DerError> {
        if self.depth == 0 {
            Ok(self.root_children)
        } else {
            Ok(self.frame(self.parent_index()?)?.children)
        }
    }
    fn set_current_children(&mut self, value: usize) -> Result<(), DerError> {
        if self.depth == 0 {
            self.root_children = value;
            return Ok(());
        }
        let parent = self.parent_index()?;
        match self.frames.get_mut(parent) {
            Some(frame) => {
                frame.children = value;
                Ok(())
            }
            None => Err(DerError::DepthLimit),
        }
    }

    fn parent_index(&self) -> Result<usize, DerError> {
        self.depth.checked_sub(1).ok_or(DerError::DepthLimit)
    }
}

fn byte(input: &[u8], position: usize) -> Result<u8, DerError> {
    input.get(position).copied().ok_or(DerError::Truncated)
}

fn parse_tag(input: &[u8], start: usize, limit: usize) -> Result<(Tag, usize), DerError> {
    let first = byte(input, start)?;
    let class = match first >> 6 {
        0 => TagClass::Universal,
        1 => TagClass::Application,
        2 => TagClass::ContextSpecific,
        _ => TagClass::Private,
    };
    let constructed = first & 0x20 != 0;
    let low = first & 0x1f;
    let mut position = start.checked_add(1).ok_or(DerError::TagOverflow)?;
    if low != 0x1f {
        if matches!(class, TagClass::Universal) && low == 0 {
            return Err(DerError::EndOfContents);
        }
        return Ok((Tag::new(class, constructed, u64::from(low)), position));
    }
    let mut number = 0_u64;
    let mut count = 1_usize;
    loop {
        count = count
            .checked_add(1)
            .ok_or(DerError::IdentifierOctetsLimit)?;
        if count > limit {
            return Err(DerError::IdentifierOctetsLimit);
        }
        let octet = byte(input, position)?;
        position = position.checked_add(1).ok_or(DerError::TagOverflow)?;
        let group = octet & 0x7f;
        if count == 2 && group == 0 {
            return Err(DerError::NonMinimalTag);
        }
        number = number
            .checked_mul(128)
            .and_then(|value| value.checked_add(u64::from(group)))
            .ok_or(DerError::TagOverflow)?;
        if octet & 0x80 == 0 {
            break;
        }
    }
    if number < 31 {
        return Err(DerError::NonMinimalTag);
    }
    Ok((Tag::new(class, constructed, number), position))
}

fn parse_length(input: &[u8], start: usize, limit: usize) -> Result<(usize, usize), DerError> {
    let first = byte(input, start)?;
    let mut position = start.checked_add(1).ok_or(DerError::LengthOverflow)?;
    if first & 0x80 == 0 {
        return Ok((usize::from(first), position));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 {
        return Err(DerError::IndefiniteLength);
    }
    let total = count.checked_add(1).ok_or(DerError::LengthOctetsLimit)?;
    if total > limit || count > core::mem::size_of::<usize>() {
        return Err(DerError::LengthOctetsLimit);
    }
    if byte(input, position)? == 0 {
        return Err(DerError::NonMinimalLength);
    }
    let mut length = 0_usize;
    let mut remaining = count;
    while remaining > 0 {
        let octet = byte(input, position)?;
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(octet)))
            .ok_or(DerError::LengthOverflow)?;
        position = position.checked_add(1).ok_or(DerError::LengthOverflow)?;
        remaining = remaining.saturating_sub(1);
    }
    if length < 128 {
        return Err(DerError::NonMinimalLength);
    }
    Ok((length, position))
}
