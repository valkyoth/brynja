//! TLS stream record framing.

use brynja_core::{ProtocolFamily, ProtocolVersion, ReadCursor, WriteCursor};

use super::{
    ContentType, ContentTypeCode, MAX_PLAINTEXT_LENGTH, MAX_TLS12_CIPHERTEXT_LENGTH,
    MAX_TLS13_CIPHERTEXT_LENGTH, RecordError, WirePolicy,
};

const HEADER_LENGTH: usize = 5;

/// Two preserved legacy record-version bytes.
///
/// Parsing TLS 1.3 plaintext preserves this field but deliberately does not
/// use it for version selection or validation, as required by RFC 9846.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LegacyRecordVersion([u8; 2]);

/// One borrowed unprotected TLS record.
///
/// The fragment aliases the caller's input and is not copied or allocated.
///
/// ```compile_fail
/// let bytes = [22, 3, 3, 0, 1, 0];
/// let policy = brynja_protocol::WirePolicy::for_version(
///     brynja_core::ProtocolVersion::Tls13,
/// );
/// let (record, _) = brynja_protocol::TlsPlaintext::parse(policy, &bytes).unwrap();
/// println!("{record:?}");
/// ```
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TlsPlaintext<'input> {
    content_type: ContentType,
    legacy_record_version: LegacyRecordVersion,
    fragment: &'input [u8],
}

/// One borrowed protected TLS record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TlsCiphertext<'input> {
    content_type: ContentType,
    legacy_record_version: LegacyRecordVersion,
    fragment: &'input [u8],
}

impl LegacyRecordVersion {
    /// Preserves two caller-provided bytes without interpreting a version.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(bytes)
    }

    /// Returns the exact preserved wire bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 2] {
        self.0
    }

    /// Returns the default legacy version emitted by TLS 1.3 records.
    #[must_use]
    pub const fn tls13_default() -> Self {
        Self([3, 3])
    }

    /// Returns the compatibility value permitted for an initial ClientHello.
    #[must_use]
    pub const fn tls13_initial_client_hello() -> Self {
        Self([3, 1])
    }

    /// Returns the default legacy version emitted by DTLS 1.3 plaintext.
    #[must_use]
    pub const fn dtls13_default() -> Self {
        Self([254, 253])
    }

    /// Returns the compatibility value permitted for an initial ClientHello.
    #[must_use]
    pub const fn dtls13_initial_client_hello() -> Self {
        Self([254, 255])
    }
}

impl<'input> TlsPlaintext<'input> {
    /// Parses one TLS plaintext record under an already selected policy.
    ///
    /// Success returns the exact unconsumed stream suffix. Failure has no
    /// caller-visible cursor mutation.
    pub fn parse(
        policy: WirePolicy,
        input: &'input [u8],
    ) -> Result<(Self, &'input [u8]), RecordError> {
        require_tls(policy)?;
        let mut cursor = ReadCursor::new(input);
        let content_type = read_content_type(&mut cursor, policy, false)?;
        let version = read_version(&mut cursor)?;
        let length = read_u16(&mut cursor)?;
        validate_plaintext_length(content_type, length)?;
        let fragment = take(&mut cursor, length)?;
        let remaining = cursor.remaining();
        Ok((
            Self {
                content_type,
                legacy_record_version: version,
                fragment,
            },
            remaining,
        ))
    }

    /// Constructs a checked plaintext envelope for encoding.
    pub fn new(
        policy: WirePolicy,
        content_type: ContentTypeCode,
        legacy_record_version: LegacyRecordVersion,
        fragment: &'input [u8],
    ) -> Result<Self, RecordError> {
        require_tls(policy)?;
        let content_type = policy.admit_plaintext(content_type)?;
        validate_plaintext_length(content_type, fragment.len())?;
        if matches!(policy.version(), ProtocolVersion::Tls13)
            && !matches!(legacy_record_version.bytes(), [3, 3] | [3, 1])
        {
            return Err(RecordError::InvalidPlaintextVersion);
        }
        Ok(Self {
            content_type,
            legacy_record_version,
            fragment,
        })
    }

    /// Returns the admitted content type.
    #[must_use]
    pub const fn content_type(&self) -> ContentType {
        self.content_type
    }

    /// Returns the preserved, non-negotiating legacy bytes.
    #[must_use]
    pub const fn legacy_record_version(&self) -> LegacyRecordVersion {
        self.legacy_record_version
    }

    /// Returns the exact borrowed fragment.
    #[must_use]
    pub const fn fragment(&self) -> &'input [u8] {
        self.fragment
    }

    /// Returns the complete encoded length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        HEADER_LENGTH.saturating_add(self.fragment.len())
    }

    /// Writes the complete record transactionally into caller storage.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, RecordError> {
        encode_record(
            self.content_type,
            self.legacy_record_version,
            self.fragment,
            output,
        )
    }
}

impl<'input> TlsCiphertext<'input> {
    /// Parses one protected TLS 1.2 or TLS 1.3 record.
    pub fn parse(
        policy: WirePolicy,
        input: &'input [u8],
    ) -> Result<(Self, &'input [u8]), RecordError> {
        require_tls(policy)?;
        let mut cursor = ReadCursor::new(input);
        let content_type = read_content_type(&mut cursor, policy, true)?;
        let version = read_version(&mut cursor)?;
        validate_ciphertext_version(policy, version)?;
        let length = read_u16(&mut cursor)?;
        validate_ciphertext_length(policy, length)?;
        let fragment = take(&mut cursor, length)?;
        let remaining = cursor.remaining();
        Ok((
            Self {
                content_type,
                legacy_record_version: version,
                fragment,
            },
            remaining,
        ))
    }

    /// Constructs a checked protected envelope for encoding.
    pub fn new(
        policy: WirePolicy,
        content_type: ContentTypeCode,
        legacy_record_version: LegacyRecordVersion,
        fragment: &'input [u8],
    ) -> Result<Self, RecordError> {
        require_tls(policy)?;
        let content_type = policy.admit_ciphertext(content_type)?;
        validate_ciphertext_version(policy, legacy_record_version)?;
        validate_ciphertext_length(policy, fragment.len())?;
        Ok(Self {
            content_type,
            legacy_record_version,
            fragment,
        })
    }

    /// Returns the admitted outer content type.
    #[must_use]
    pub const fn content_type(&self) -> ContentType {
        self.content_type
    }

    /// Returns the exact outer legacy-version bytes.
    #[must_use]
    pub const fn legacy_record_version(&self) -> LegacyRecordVersion {
        self.legacy_record_version
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

    /// Writes the complete record transactionally into caller storage.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, RecordError> {
        encode_record(
            self.content_type,
            self.legacy_record_version,
            self.fragment,
            output,
        )
    }
}

fn require_tls(policy: WirePolicy) -> Result<(), RecordError> {
    if matches!(policy.version().family(), ProtocolFamily::Tls) {
        Ok(())
    } else {
        Err(RecordError::ProfileMismatch)
    }
}

fn read_content_type(
    cursor: &mut ReadCursor<'_>,
    policy: WirePolicy,
    ciphertext: bool,
) -> Result<ContentType, RecordError> {
    let bytes = take(cursor, 1)?;
    let code = match bytes.first() {
        Some(code) => ContentTypeCode::classify(*code),
        None => return Err(RecordError::Truncated),
    };
    if ciphertext {
        policy.admit_ciphertext(code)
    } else {
        policy.admit_plaintext(code)
    }
}

fn read_version(cursor: &mut ReadCursor<'_>) -> Result<LegacyRecordVersion, RecordError> {
    let bytes = cursor
        .take_array::<2>()
        .map_err(|_| RecordError::Truncated)?;
    Ok(LegacyRecordVersion::from_bytes(*bytes))
}

fn read_u16(cursor: &mut ReadCursor<'_>) -> Result<usize, RecordError> {
    let bytes = cursor
        .take_array::<2>()
        .map_err(|_| RecordError::Truncated)?;
    Ok(usize::from(u16::from_be_bytes(*bytes)))
}

fn take<'input>(
    cursor: &mut ReadCursor<'input>,
    length: usize,
) -> Result<&'input [u8], RecordError> {
    cursor.take(length).map_err(|_| RecordError::Truncated)
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

fn validate_ciphertext_version(
    policy: WirePolicy,
    version: LegacyRecordVersion,
) -> Result<(), RecordError> {
    if matches!(policy.version(), ProtocolVersion::Tls13) && version.bytes() != [3, 3] {
        Err(RecordError::InvalidCiphertextVersion)
    } else {
        Ok(())
    }
}

fn validate_ciphertext_length(policy: WirePolicy, length: usize) -> Result<(), RecordError> {
    let maximum = if matches!(policy.version(), ProtocolVersion::Tls13) {
        MAX_TLS13_CIPHERTEXT_LENGTH
    } else {
        MAX_TLS12_CIPHERTEXT_LENGTH
    };
    if length > maximum {
        Err(RecordError::RecordOverflow)
    } else if length == 0 && matches!(policy.version(), ProtocolVersion::Tls13) {
        Err(RecordError::EmptyFragment)
    } else {
        Ok(())
    }
}

fn encode_record(
    content_type: ContentType,
    version: LegacyRecordVersion,
    fragment: &[u8],
    output: &mut [u8],
) -> Result<usize, RecordError> {
    let total = HEADER_LENGTH
        .checked_add(fragment.len())
        .ok_or(RecordError::LengthOverflow)?;
    if output.len() < total {
        return Err(RecordError::InsufficientOutput);
    }
    let length = u16::try_from(fragment.len()).map_err(|_| RecordError::RecordOverflow)?;
    let type_bytes = [content_type.code()];
    let version_bytes = version.bytes();
    let length_bytes = length.to_be_bytes();
    let mut cursor = WriteCursor::new(output);
    cursor
        .write_parts(&[&type_bytes, &version_bytes, &length_bytes, fragment])
        .map_err(|_| RecordError::InsufficientOutput)?;
    Ok(total)
}
