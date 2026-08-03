//! Transactional caller-buffer output construction.

/// A closed, value-free reason that caller-buffer output failed.
///
/// The error carries neither output bytes, offsets, requested lengths, nor
/// available lengths, so it is safe to format in diagnostics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum WriteError {
    /// The complete requested output range was not available.
    InsufficientCapacity,
    /// Computing a requested length or end offset overflowed `usize`.
    LengthOverflow,
    /// Explicit completion found unwritten output capacity.
    TrailingCapacity,
}

/// An allocation-free cursor over a caller-owned mutable byte buffer.
///
/// Each mutation method is transactional: it checks the complete destination
/// range before changing any byte, then advances only after the entire write.
/// [`write_parts`](Self::write_parts) makes several borrowed inputs one
/// transaction. Separate successful method calls are separate transactions.
/// The cursor deliberately does not implement `Clone`, `Copy`, `Debug`, or
/// `Display`.
///
/// This type does not own secrets and makes no erasure guarantee. A caller
/// remains responsible for clearing sensitive input and output storage.
///
/// ```compile_fail
/// let mut output = [0_u8; 3];
/// let cursor = brynja_core::WriteCursor::new(&mut output);
/// println!("{cursor:?}");
/// ```
///
/// ```compile_fail
/// let mut output = [0_u8; 3];
/// let cursor = brynja_core::WriteCursor::new(&mut output);
/// let _fork = cursor.clone();
/// ```
///
/// ```compile_fail
/// let mut output = [0_u8; 3];
/// let mut cursor = brynja_core::WriteCursor::new(&mut output);
/// output.fill(7);
/// cursor.write(&[1, 2, 3]).unwrap();
/// ```
#[must_use = "a write cursor must be explicitly completed or inspected"]
pub struct WriteCursor<'output> {
    output: &'output mut [u8],
    position: usize,
}

impl<'output> WriteCursor<'output> {
    /// Borrows a caller-owned output slice without changing it.
    pub const fn new(output: &'output mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    /// Returns the number of bytes written successfully.
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns the unwritten output capacity.
    pub const fn remaining_len(&self) -> usize {
        debug_assert!(self.position <= self.output.len());
        self.output.len().saturating_sub(self.position)
    }

    /// Returns whether the complete output buffer has been written.
    pub const fn is_finished(&self) -> bool {
        self.position == self.output.len()
    }

    /// Borrows the prefix produced by successful writes.
    pub fn written(&self) -> &[u8] {
        debug_assert!(self.position <= self.output.len());
        match self.output.get(..self.position) {
            Some(written) => written,
            None => &[],
        }
    }

    /// Writes one complete borrowed byte slice.
    ///
    /// Overflow or insufficient capacity leaves every output byte and the
    /// cursor position unchanged.
    pub fn write(&mut self, input: &[u8]) -> Result<(), WriteError> {
        let end = self.checked_end(input.len())?;
        let destination = match self.output.get_mut(self.position..end) {
            Some(destination) => destination,
            None => return Err(WriteError::InsufficientCapacity),
        };
        for (output, byte) in destination.iter_mut().zip(input.iter()) {
            *output = *byte;
        }
        self.position = end;
        Ok(())
    }

    /// Writes several borrowed slices as one transaction.
    ///
    /// All part lengths and the complete destination are checked before the
    /// first byte changes. Empty parts are accepted.
    pub fn write_parts(&mut self, parts: &[&[u8]]) -> Result<(), WriteError> {
        let mut total = 0_usize;
        for part in parts {
            total = match total.checked_add(part.len()) {
                Some(total) => total,
                None => return Err(WriteError::LengthOverflow),
            };
        }
        let end = self.checked_end(total)?;
        let destination = match self.output.get_mut(self.position..end) {
            Some(destination) => destination,
            None => return Err(WriteError::InsufficientCapacity),
        };
        let bytes = parts.iter().flat_map(|part| part.iter());
        for (output, byte) in destination.iter_mut().zip(bytes) {
            *output = *byte;
        }
        self.position = end;
        Ok(())
    }

    /// Writes `length` copies of one byte as one transaction.
    ///
    /// This supports deterministic padding and reserved-field initialization
    /// without allocation. It does not define protocol padding semantics.
    pub fn write_repeated(&mut self, byte: u8, length: usize) -> Result<(), WriteError> {
        let end = self.checked_end(length)?;
        let destination = match self.output.get_mut(self.position..end) {
            Some(destination) => destination,
            None => return Err(WriteError::InsufficientCapacity),
        };
        destination.fill(byte);
        self.position = end;
        Ok(())
    }

    /// Requires exact use of the caller's output buffer and returns it.
    ///
    /// Consuming `self` prevents accidental writes after completion.
    pub fn finish(self) -> Result<&'output mut [u8], WriteError> {
        if self.is_finished() {
            Ok(self.output)
        } else {
            Err(WriteError::TrailingCapacity)
        }
    }

    fn checked_end(&self, length: usize) -> Result<usize, WriteError> {
        let end = match self.position.checked_add(length) {
            Some(end) => end,
            None => return Err(WriteError::LengthOverflow),
        };
        if end > self.output.len() {
            Err(WriteError::InsufficientCapacity)
        } else {
            Ok(end)
        }
    }
}
