//! DTLS 1.2 protected record framing.

use brynja_core::{ProtocolVersion, ReadCursor, WriteCursor};

use super::{
    ContentType, ContentTypeCode, LegacyRecordVersion, MAX_TLS12_CIPHERTEXT_LENGTH, RecordError,
    WirePolicy,
};

const HEADER_LENGTH: usize = 13;

/// One borrowed protected DTLS 1.2 record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Dtls12Ciphertext<'input> {
    content_type: ContentType,
    legacy_record_version: LegacyRecordVersion,
    epoch: u16,
    sequence_number: [u8; 6],
    fragment: &'input [u8],
}

impl<'input> Dtls12Ciphertext<'input> {
    /// Constructs a checked protected DTLS 1.2 envelope for encoding.
    pub fn new(
        policy: WirePolicy,
        content_type: ContentTypeCode,
        legacy_record_version: LegacyRecordVersion,
        epoch: u16,
        sequence_number: [u8; 6],
        fragment: &'input [u8],
    ) -> Result<Self, RecordError> {
        if !matches!(policy.version(), ProtocolVersion::Dtls12) {
            return Err(RecordError::ProfileMismatch);
        }
        let content_type = policy.admit_ciphertext(content_type)?;
        validate_length(fragment.len())?;
        Ok(Self {
            content_type,
            legacy_record_version,
            epoch,
            sequence_number,
            fragment,
        })
    }

    /// Parses one protected DTLS 1.2 record and returns the datagram suffix.
    pub fn parse(
        policy: WirePolicy,
        input: &'input [u8],
    ) -> Result<(Self, &'input [u8]), RecordError> {
        if !matches!(policy.version(), ProtocolVersion::Dtls12) {
            return Err(RecordError::ProfileMismatch);
        }
        let mut cursor = ReadCursor::new(input);
        let code = read_byte(&mut cursor)?;
        let content_type = policy.admit_ciphertext(ContentTypeCode::classify(code))?;
        let version = read_version(&mut cursor)?;
        let epoch = read_u16(&mut cursor)?;
        let sequence_number = *cursor
            .take_array::<6>()
            .map_err(|_| RecordError::Truncated)?;
        let length = usize::from(read_u16(&mut cursor)?);
        validate_length(length)?;
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

    /// Returns the admitted outer content type.
    #[must_use]
    pub const fn content_type(&self) -> ContentType {
        self.content_type
    }

    /// Returns the preserved record-version bytes.
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

    /// Returns the exact borrowed protected fragment.
    #[must_use]
    pub const fn fragment(&self) -> &'input [u8] {
        self.fragment
    }

    /// Returns the complete encoded length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        HEADER_LENGTH.saturating_add(self.fragment.len())
    }

    /// Writes the complete parsed record transactionally.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, RecordError> {
        let total = HEADER_LENGTH
            .checked_add(self.fragment.len())
            .ok_or(RecordError::LengthOverflow)?;
        if output.len() < total {
            return Err(RecordError::InsufficientOutput);
        }
        let length = u16::try_from(self.fragment.len())
            .map_err(|_| RecordError::RecordOverflow)?
            .to_be_bytes();
        let content_type = [self.content_type.code()];
        let version = self.legacy_record_version.bytes();
        let epoch = self.epoch.to_be_bytes();
        let mut cursor = WriteCursor::new(output);
        cursor
            .write_parts(&[
                &content_type,
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

fn validate_length(length: usize) -> Result<(), RecordError> {
    if length > MAX_TLS12_CIPHERTEXT_LENGTH {
        Err(RecordError::RecordOverflow)
    } else {
        Ok(())
    }
}
