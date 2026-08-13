//! DTLS datagram record framing.

use brynja_core::{ProtocolFamily, ProtocolVersion, ReadCursor, WriteCursor};

use super::{
    ContentType, ContentTypeCode, LegacyRecordVersion, MAX_PLAINTEXT_LENGTH,
    MAX_TLS13_CIPHERTEXT_LENGTH, RecordError, WirePolicy,
};

const PLAINTEXT_HEADER_LENGTH: usize = 13;
const UNIFIED_FIXED_BITS: u8 = 0x20;
const UNIFIED_FIXED_MASK: u8 = 0xe0;
const CID_BIT: u8 = 0x10;
const LONG_SEQUENCE_BIT: u8 = 0x08;
const LENGTH_BIT: u8 = 0x04;

/// One borrowed unprotected DTLS record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DtlsPlaintext<'input> {
    content_type: ContentType,
    legacy_record_version: LegacyRecordVersion,
    epoch: u16,
    sequence_number: [u8; 6],
    fragment: &'input [u8],
}

/// Expected DTLS 1.3 Connection ID layout for one selected association.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Dtls13CiphertextConfig {
    connection_id_length: u8,
}

/// The encoded truncated DTLS 1.3 record sequence number.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Dtls13Sequence {
    /// An eight-bit truncated sequence number.
    Short(u8),
    /// A sixteen-bit truncated sequence number.
    Long(u16),
}

/// Caller-supplied DTLS 1.3 unified-header fields for encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Dtls13CiphertextHeader<'cid> {
    epoch_bits: u8,
    connection_id: &'cid [u8],
    sequence: Dtls13Sequence,
    length_present: bool,
}

/// One borrowed protected DTLS 1.3 record with its exact header bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Dtls13Ciphertext<'input> {
    unified_header: &'input [u8],
    connection_id: &'input [u8],
    sequence: Dtls13Sequence,
    epoch_bits: u8,
    length_present: bool,
    encrypted_record: &'input [u8],
}

impl<'input> DtlsPlaintext<'input> {
    /// Constructs a checked DTLS plaintext envelope for encoding.
    pub fn new(
        policy: WirePolicy,
        content_type: ContentTypeCode,
        legacy_record_version: LegacyRecordVersion,
        epoch: u16,
        sequence_number: [u8; 6],
        fragment: &'input [u8],
    ) -> Result<Self, RecordError> {
        require_dtls(policy)?;
        let content_type = policy.admit_plaintext(content_type)?;
        if matches!(policy.version(), ProtocolVersion::Dtls13) && epoch != 0 {
            return Err(RecordError::InvalidPlaintextEpoch);
        }
        if matches!(policy.version(), ProtocolVersion::Dtls13)
            && !matches!(legacy_record_version.bytes(), [254, 253] | [254, 255])
        {
            return Err(RecordError::InvalidPlaintextVersion);
        }
        validate_plaintext_length(content_type, fragment.len())?;
        Ok(Self {
            content_type,
            legacy_record_version,
            epoch,
            sequence_number,
            fragment,
        })
    }

    /// Parses one DTLS 1.2 or DTLS 1.3 plaintext record.
    pub fn parse(
        policy: WirePolicy,
        input: &'input [u8],
    ) -> Result<(Self, &'input [u8]), RecordError> {
        require_dtls(policy)?;
        let mut cursor = ReadCursor::new(input);
        let code = read_byte(&mut cursor)?;
        let content_type = policy.admit_plaintext(ContentTypeCode::classify(code))?;
        let version = read_version(&mut cursor)?;
        let epoch = read_u16(&mut cursor)?;
        if matches!(policy.version(), ProtocolVersion::Dtls13) && epoch != 0 {
            return Err(RecordError::InvalidPlaintextEpoch);
        }
        let sequence_number = *cursor
            .take_array::<6>()
            .map_err(|_| RecordError::Truncated)?;
        let length = usize::from(read_u16(&mut cursor)?);
        validate_plaintext_length(content_type, length)?;
        let fragment = cursor.take(length).map_err(|_| RecordError::Truncated)?;
        let remaining = cursor.remaining();
        Ok((
            Self {
                content_type,
                legacy_record_version: version,
                epoch,
                sequence_number,
                fragment,
            },
            remaining,
        ))
    }

    /// Returns the admitted content type.
    #[must_use]
    pub const fn content_type(&self) -> ContentType {
        self.content_type
    }

    /// Returns preserved non-negotiating legacy-version bytes.
    #[must_use]
    pub const fn legacy_record_version(&self) -> LegacyRecordVersion {
        self.legacy_record_version
    }

    /// Returns the exact encoded epoch.
    #[must_use]
    pub const fn epoch(&self) -> u16 {
        self.epoch
    }

    /// Returns the exact encoded 48-bit sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> [u8; 6] {
        self.sequence_number
    }

    /// Returns the exact borrowed fragment.
    #[must_use]
    pub const fn fragment(&self) -> &'input [u8] {
        self.fragment
    }

    /// Writes the complete parsed record transactionally.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, RecordError> {
        let total = PLAINTEXT_HEADER_LENGTH
            .checked_add(self.fragment.len())
            .ok_or(RecordError::LengthOverflow)?;
        if output.len() < total {
            return Err(RecordError::InsufficientOutput);
        }
        let length = u16::try_from(self.fragment.len())
            .map_err(|_| RecordError::RecordOverflow)?
            .to_be_bytes();
        let type_bytes = [self.content_type.code()];
        let version = self.legacy_record_version.bytes();
        let epoch = self.epoch.to_be_bytes();
        let mut cursor = WriteCursor::new(output);
        cursor
            .write_parts(&[
                &type_bytes,
                &version,
                &epoch,
                &self.sequence_number,
                &length,
                self.fragment,
            ])
            .map_err(|_| RecordError::InsufficientOutput)?;
        Ok(total)
    }
}

impl Dtls13CiphertextConfig {
    /// Creates an exact selected-association CID layout.
    pub fn new(connection_id_length: usize) -> Result<Self, RecordError> {
        let connection_id_length =
            u8::try_from(connection_id_length).map_err(|_| RecordError::ConnectionIdTooLong)?;
        Ok(Self {
            connection_id_length,
        })
    }

    /// Returns the exact negotiated CID byte length.
    #[must_use]
    pub const fn connection_id_length(self) -> usize {
        self.connection_id_length as usize
    }
}

impl<'cid> Dtls13CiphertextHeader<'cid> {
    /// Creates checked caller-supplied unified-header fields.
    pub fn new(
        epoch_bits: u8,
        connection_id: &'cid [u8],
        sequence: Dtls13Sequence,
        length_present: bool,
    ) -> Result<Self, RecordError> {
        if epoch_bits > 3 {
            return Err(RecordError::InvalidUnifiedHeader);
        }
        let _ = u8::try_from(connection_id.len()).map_err(|_| RecordError::ConnectionIdTooLong)?;
        Ok(Self {
            epoch_bits,
            connection_id,
            sequence,
            length_present,
        })
    }

    /// Returns the low two encoded epoch bits.
    #[must_use]
    pub const fn epoch_bits(self) -> u8 {
        self.epoch_bits
    }

    /// Returns the exact borrowed Connection ID.
    #[must_use]
    pub const fn connection_id(self) -> &'cid [u8] {
        self.connection_id
    }

    /// Returns the exact truncated sequence number.
    #[must_use]
    pub const fn sequence(self) -> Dtls13Sequence {
        self.sequence
    }

    /// Reports whether the encoded header includes a length field.
    #[must_use]
    pub const fn length_present(self) -> bool {
        self.length_present
    }
}

impl<'input> Dtls13Ciphertext<'input> {
    /// Parses one protected DTLS 1.3 record under an exact CID context.
    ///
    /// A record without a length field consumes the rest of the datagram.
    pub fn parse(
        policy: WirePolicy,
        config: Dtls13CiphertextConfig,
        input: &'input [u8],
    ) -> Result<(Self, &'input [u8]), RecordError> {
        if !matches!(policy.version(), ProtocolVersion::Dtls13) {
            return Err(RecordError::ProfileMismatch);
        }
        let mut cursor = ReadCursor::new(input);
        let first = read_byte(&mut cursor)?;
        if first & UNIFIED_FIXED_MASK != UNIFIED_FIXED_BITS {
            return Err(RecordError::InvalidUnifiedHeader);
        }
        let cid_present = first & CID_BIT != 0;
        if cid_present != (config.connection_id_length != 0) {
            return Err(RecordError::ConnectionIdMismatch);
        }
        let connection_id = cursor
            .take(config.connection_id_length())
            .map_err(|_| RecordError::Truncated)?;
        let sequence = if first & LONG_SEQUENCE_BIT == 0 {
            Dtls13Sequence::Short(read_byte(&mut cursor)?)
        } else {
            Dtls13Sequence::Long(read_u16(&mut cursor)?)
        };
        let length_present = first & LENGTH_BIT != 0;
        let encrypted_length = if length_present {
            usize::from(read_u16(&mut cursor)?)
        } else {
            cursor.remaining_len()
        };
        validate_ciphertext_length(encrypted_length)?;
        let encrypted_record = cursor
            .take(encrypted_length)
            .map_err(|_| RecordError::Truncated)?;
        let remaining = cursor.remaining();
        let header_length = input
            .len()
            .checked_sub(encrypted_record.len())
            .and_then(|length| length.checked_sub(remaining.len()))
            .ok_or(RecordError::LengthOverflow)?;
        let unified_header = input.get(..header_length).ok_or(RecordError::Truncated)?;
        Ok((
            Self {
                unified_header,
                connection_id,
                sequence,
                epoch_bits: first & 3,
                length_present,
                encrypted_record,
            },
            remaining,
        ))
    }

    /// Returns the exact encoded unified header.
    #[must_use]
    pub const fn unified_header(&self) -> &'input [u8] {
        self.unified_header
    }

    /// Returns the exact borrowed Connection ID.
    #[must_use]
    pub const fn connection_id(&self) -> &'input [u8] {
        self.connection_id
    }

    /// Returns the encoded truncated sequence number.
    #[must_use]
    pub const fn sequence(&self) -> Dtls13Sequence {
        self.sequence
    }

    /// Returns the low two encoded epoch bits.
    #[must_use]
    pub const fn epoch_bits(&self) -> u8 {
        self.epoch_bits
    }

    /// Reports whether the wire header contained an explicit length.
    #[must_use]
    pub const fn length_present(&self) -> bool {
        self.length_present
    }

    /// Returns the exact borrowed protected fragment.
    #[must_use]
    pub const fn encrypted_record(&self) -> &'input [u8] {
        self.encrypted_record
    }

    /// Writes the complete parsed record transactionally.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, RecordError> {
        let total = self
            .unified_header
            .len()
            .checked_add(self.encrypted_record.len())
            .ok_or(RecordError::LengthOverflow)?;
        if output.len() < total {
            return Err(RecordError::InsufficientOutput);
        }
        let mut cursor = WriteCursor::new(output);
        cursor
            .write_parts(&[self.unified_header, self.encrypted_record])
            .map_err(|_| RecordError::InsufficientOutput)?;
        Ok(total)
    }
}

/// Encodes one checked DTLS 1.3 unified-header record.
pub fn encode_dtls13_ciphertext(
    header: Dtls13CiphertextHeader<'_>,
    encrypted_record: &[u8],
    output: &mut [u8],
) -> Result<usize, RecordError> {
    validate_ciphertext_length(encrypted_record.len())?;
    let sequence_length = match header.sequence {
        Dtls13Sequence::Short(_) => 1_usize,
        Dtls13Sequence::Long(_) => 2_usize,
    };
    let length_length = if header.length_present {
        2_usize
    } else {
        0_usize
    };
    let total = 1_usize
        .checked_add(header.connection_id.len())
        .and_then(|value| value.checked_add(sequence_length))
        .and_then(|value| value.checked_add(length_length))
        .and_then(|value| value.checked_add(encrypted_record.len()))
        .ok_or(RecordError::LengthOverflow)?;
    if output.len() < total {
        return Err(RecordError::InsufficientOutput);
    }
    let mut first = UNIFIED_FIXED_BITS | header.epoch_bits;
    if !header.connection_id.is_empty() {
        first |= CID_BIT;
    }
    if matches!(header.sequence, Dtls13Sequence::Long(_)) {
        first |= LONG_SEQUENCE_BIT;
    }
    if header.length_present {
        first |= LENGTH_BIT;
    }
    let first_bytes = [first];
    let sequence_bytes = match header.sequence {
        Dtls13Sequence::Short(value) => [0, value],
        Dtls13Sequence::Long(value) => value.to_be_bytes(),
    };
    let sequence = if matches!(header.sequence, Dtls13Sequence::Short(_)) {
        sequence_bytes.get(1..).ok_or(RecordError::LengthOverflow)?
    } else {
        sequence_bytes.as_slice()
    };
    let length_value = u16::try_from(encrypted_record.len())
        .map_err(|_| RecordError::RecordOverflow)?
        .to_be_bytes();
    let length = if header.length_present {
        length_value.as_slice()
    } else {
        &[]
    };
    let mut cursor = WriteCursor::new(output);
    cursor
        .write_parts(&[
            &first_bytes,
            header.connection_id,
            sequence,
            length,
            encrypted_record,
        ])
        .map_err(|_| RecordError::InsufficientOutput)?;
    Ok(total)
}

fn require_dtls(policy: WirePolicy) -> Result<(), RecordError> {
    if matches!(policy.version().family(), ProtocolFamily::Dtls) {
        Ok(())
    } else {
        Err(RecordError::ProfileMismatch)
    }
}

fn read_byte(cursor: &mut ReadCursor<'_>) -> Result<u8, RecordError> {
    cursor
        .take(1)
        .map_err(|_| RecordError::Truncated)?
        .first()
        .copied()
        .ok_or(RecordError::Truncated)
}

fn read_u16(cursor: &mut ReadCursor<'_>) -> Result<u16, RecordError> {
    let bytes = cursor
        .take_array::<2>()
        .map_err(|_| RecordError::Truncated)?;
    Ok(u16::from_be_bytes(*bytes))
}

fn read_version(cursor: &mut ReadCursor<'_>) -> Result<LegacyRecordVersion, RecordError> {
    let bytes = cursor
        .take_array::<2>()
        .map_err(|_| RecordError::Truncated)?;
    Ok(LegacyRecordVersion::from_bytes(*bytes))
}

fn validate_plaintext_length(content_type: ContentType, length: usize) -> Result<(), RecordError> {
    if length > MAX_PLAINTEXT_LENGTH {
        return Err(RecordError::RecordOverflow);
    }
    if length == 0 && !matches!(content_type, ContentType::ApplicationData) {
        return Err(RecordError::EmptyFragment);
    }
    Ok(())
}

fn validate_ciphertext_length(length: usize) -> Result<(), RecordError> {
    if length > MAX_TLS13_CIPHERTEXT_LENGTH {
        Err(RecordError::RecordOverflow)
    } else if length == 0 {
        Err(RecordError::EmptyFragment)
    } else {
        Ok(())
    }
}
