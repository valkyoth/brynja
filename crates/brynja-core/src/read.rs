//! Transactional borrowed input consumption.

use core::convert::TryFrom;

use crate::Length;

/// A closed, value-free reason that borrowed input consumption failed.
///
/// The error carries neither input bytes, offsets, requested lengths, nor
/// available lengths, so it is safe to format in diagnostics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ReadError {
    /// The requested byte range was not completely available.
    Truncated,
    /// Computing the requested end offset overflowed `usize`.
    LengthOverflow,
    /// Explicit completion found unconsumed input.
    TrailingData,
}

/// A borrowed, allocation-free cursor over caller-owned bytes.
///
/// Every read is transactional: success advances by exactly the requested
/// length, while failure leaves the cursor unchanged. Returned slices borrow
/// directly from the original input. The cursor deliberately does not
/// implement `Clone`, `Copy`, `Debug`, or `Display`.
///
/// Call [`finish`](Self::finish) when exact input consumption is required.
///
/// ```compile_fail
/// let input = [1_u8, 2, 3];
/// let cursor = brynja_core::ReadCursor::new(&input);
/// println!("{cursor:?}");
/// ```
///
/// ```compile_fail
/// let input = [1_u8, 2, 3];
/// let cursor = brynja_core::ReadCursor::new(&input);
/// let _fork = cursor.clone();
/// ```
///
/// ```compile_fail
/// fn invalid<'a>() -> &'a [u8] {
///     let input = [1_u8, 2, 3];
///     let mut cursor = brynja_core::ReadCursor::new(&input);
///     cursor.take(3).unwrap()
/// }
/// ```
#[must_use = "a read cursor must be explicitly consumed or inspected"]
pub struct ReadCursor<'input> {
    input: &'input [u8],
    position: usize,
}

impl<'input> ReadCursor<'input> {
    /// Borrows an input slice without reading or allocating.
    pub const fn new(input: &'input [u8]) -> Self {
        Self { input, position: 0 }
    }

    /// Returns the number of bytes consumed successfully.
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns the number of bytes that remain unconsumed.
    pub const fn remaining_len(&self) -> usize {
        debug_assert!(self.position <= self.input.len());
        self.input.len().saturating_sub(self.position)
    }

    /// Returns whether all input has been consumed.
    pub const fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }

    /// Borrows the unconsumed suffix without advancing the cursor.
    pub fn remaining(&self) -> &'input [u8] {
        debug_assert!(self.position <= self.input.len());
        match self.input.get(self.position..) {
            Some(remaining) => remaining,
            None => &[],
        }
    }

    /// Borrows and consumes exactly `length` bytes.
    ///
    /// Overflow or truncation leaves the cursor position unchanged.
    pub fn take(&mut self, length: usize) -> Result<&'input [u8], ReadError> {
        let (end, bytes) = self.preview(length)?;
        self.position = end;
        Ok(bytes)
    }

    fn preview(&self, length: usize) -> Result<(usize, &'input [u8]), ReadError> {
        let end = match self.position.checked_add(length) {
            Some(end) => end,
            None => return Err(ReadError::LengthOverflow),
        };
        let bytes = match self.input.get(self.position..end) {
            Some(bytes) => bytes,
            None => return Err(ReadError::Truncated),
        };
        Ok((end, bytes))
    }

    /// Borrows and consumes a semantically typed byte length.
    pub fn take_length<const MAX: usize>(
        &mut self,
        length: Length<MAX>,
    ) -> Result<&'input [u8], ReadError> {
        self.take(length.get())
    }

    /// Borrows and consumes exactly `N` bytes as an array reference.
    pub fn take_array<const N: usize>(&mut self) -> Result<&'input [u8; N], ReadError> {
        let (end, bytes) = self.preview(N)?;
        let array = match <&[u8; N]>::try_from(bytes) {
            Ok(array) => array,
            Err(_) => return Err(ReadError::Truncated),
        };
        self.position = end;
        Ok(array)
    }

    /// Requires that all input has been consumed.
    ///
    /// Consuming `self` prevents accidental reuse after the completion check.
    pub const fn finish(self) -> Result<(), ReadError> {
        if self.is_finished() {
            Ok(())
        } else {
            Err(ReadError::TrailingData)
        }
    }
}
