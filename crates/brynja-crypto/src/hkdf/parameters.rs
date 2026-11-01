const TLS_PREFIX: &[u8; 6] = b"tls13 ";

/// Value-free rejection of public HKDF/label parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParameterError {
    /// A digest width is zero or its 255-block limit cannot be represented.
    HashLength,
    /// Requested output exceeds the RFC 5869 255-block limit.
    ExpansionLength,
    /// Output does not fit the TLS field or differs from a supplied label's length.
    TlsOutputLength,
    /// Unprefixed TLS label must contain 1 through 249 bytes.
    LabelLength,
    /// TLS context must contain at most 255 bytes.
    ContextLength,
    /// The destination cannot hold the complete encoding; it is unchanged.
    DestinationLength,
}

/// Checked RFC 5869 output length and exact number of HMAC expansion blocks.
///
/// Zero-byte output needs zero blocks. Hash width is explicit public metadata,
/// not algorithm admission; the key-owning API obtains it from its sealed
/// algorithm identity rather than accepting caller-selected hash widths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpansionLength {
    bytes: usize,
    blocks: u8,
}

impl ExpansionLength {
    /// Checks `output_bytes <= 255 * hash_bytes` without wrapping arithmetic.
    pub fn new(hash_bytes: usize, output_bytes: usize) -> Result<Self, ParameterError> {
        if hash_bytes == 0 {
            return Err(ParameterError::HashLength);
        }
        let limit = hash_bytes
            .checked_mul(255)
            .ok_or(ParameterError::HashLength)?;
        if output_bytes > limit {
            return Err(ParameterError::ExpansionLength);
        }
        let whole = output_bytes
            .checked_div(hash_bytes)
            .ok_or(ParameterError::HashLength)?;
        let remainder = output_bytes
            .checked_rem(hash_bytes)
            .ok_or(ParameterError::HashLength)?;
        let blocks = whole
            .checked_add(usize::from(remainder != 0))
            .and_then(|n| u8::try_from(n).ok())
            .ok_or(ParameterError::ExpansionLength)?;
        Ok(Self {
            bytes: output_bytes,
            blocks,
        })
    }

    /// The admitted output size, including a possible partial final block.
    pub const fn bytes(self) -> usize {
        self.bytes
    }

    /// Number of required blocks, in the inclusive range 0 through 255.
    pub const fn blocks(self) -> u8 {
        self.blocks
    }

    /// Exact one-byte counters, never including zero or wrapping after 255.
    pub fn counters(self) -> core::ops::RangeInclusive<u8> {
        1..=self.blocks
    }
}

/// Validated TLS 1.3 HKDF label, before cryptographic expansion.
///
/// `label` excludes the mandatory `tls13 ` prefix; bytes are encoded exactly,
/// without a NUL terminator, text normalization or implicit transcript hashing.
/// This checks TLS wire bounds, not the hash-dependent HKDF output bound.
/// Label/context are borrowed metadata, not clearing secret owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tls13Label<'a> {
    label: &'a [u8],
    context: &'a [u8],
    output_bytes: u16,
    label_bytes: u8,
    context_bytes: u8,
    encoded_bytes: usize,
}

impl<'a> Tls13Label<'a> {
    /// Validates every field before any destination is borrowed or modified.
    pub fn new(
        label: &'a [u8],
        context: &'a [u8],
        output_bytes: usize,
    ) -> Result<Self, ParameterError> {
        if label.is_empty() {
            return Err(ParameterError::LabelLength);
        }
        let label_bytes = label
            .len()
            .checked_add(TLS_PREFIX.len())
            .and_then(|n| u8::try_from(n).ok())
            .ok_or(ParameterError::LabelLength)?;
        let context_bytes =
            u8::try_from(context.len()).map_err(|_| ParameterError::ContextLength)?;
        let output_bytes =
            u16::try_from(output_bytes).map_err(|_| ParameterError::TlsOutputLength)?;
        let encoded_bytes = usize::from(label_bytes)
            .checked_add(usize::from(context_bytes))
            .and_then(|n| n.checked_add(4))
            .ok_or(ParameterError::DestinationLength)?;
        Ok(Self {
            label,
            context,
            output_bytes,
            label_bytes,
            context_bytes,
            encoded_bytes,
        })
    }

    /// Exact encoding size, at most 514 bytes including the four length bytes.
    pub const fn encoded_len(self) -> usize {
        self.encoded_bytes
    }

    /// Output size committed to by this label, not the label encoding size.
    pub const fn output_len(self) -> usize {
        self.output_bytes as usize
    }

    /// Writes one complete label and returns its initialized prefix.
    ///
    /// Insufficient capacity leaves all destination bytes unchanged. Excess
    /// capacity is untouched. There is no fallible work after the first write.
    /// Safe borrows prohibit exact or partial overlap with label/context; disjoint
    /// slices of one allocation are allowed. No unsafe aliasing workaround exists.
    /// This is a low-level wire encoder, not an expansion operation. Passing its
    /// bytes to raw `Prk::expand` does not bind the output length. For key
    /// derivation use `Prk::expand_tls13` or `Prk::expand_label`, which do bind it.
    ///
    /// ```compile_fail
    /// use brynja_crypto::hkdf::Tls13Label;
    /// let mut storage = [b'x'; 32];
    /// let label = Tls13Label::new(&storage[..1], &[], 32).unwrap();
    /// label.encode(&mut storage).unwrap();
    /// ```
    pub fn encode<'b>(&self, destination: &'b mut [u8]) -> Result<&'b [u8], ParameterError> {
        let encoded = destination
            .get_mut(..self.encoded_bytes)
            .ok_or(ParameterError::DestinationLength)?;
        let length = self.output_bytes.to_be_bytes();
        let fields = length
            .iter()
            .chain(core::iter::once(&self.label_bytes))
            .chain(TLS_PREFIX.iter())
            .chain(self.label.iter())
            .chain(core::iter::once(&self.context_bytes))
            .chain(self.context.iter());
        for (out, byte) in encoded.iter_mut().zip(fields) {
            *out = *byte;
        }
        Ok(encoded)
    }
}
