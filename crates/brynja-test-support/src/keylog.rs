//! Repository-only RFC 9850 SSLKEYLOGFILE encoding.
//!
//! This module intentionally handles secret material for diagnostic tests. The
//! containing package is unpublished and unreachable from every production
//! package and feature. Output must receive the same protection as the traffic
//! it compromises and is never evidence of production key-log support.

/// One RFC 9850 or pinned-IANA key-log label.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KeyLogLabel {
    /// TLS 1.2 and earlier master secret.
    ClientRandom,
    /// TLS 1.3 client early-traffic secret.
    ClientEarlyTrafficSecret,
    /// TLS 1.3 early-exporter secret.
    EarlyExporterSecret,
    /// TLS 1.3 client handshake-traffic secret.
    ClientHandshakeTrafficSecret,
    /// TLS 1.3 server handshake-traffic secret.
    ServerHandshakeTrafficSecret,
    /// Initial TLS 1.3 client application-traffic secret.
    ClientTrafficSecret0,
    /// Initial TLS 1.3 server application-traffic secret.
    ServerTrafficSecret0,
    /// TLS 1.3 exporter secret.
    ExporterSecret,
    /// ECH HPKE KEM shared secret.
    EchSecret,
    /// ECH configuration used to construct the extension.
    EchConfig,
}

impl KeyLogLabel {
    /// Returns the exact uppercase registry label.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::ClientRandom => b"CLIENT_RANDOM",
            Self::ClientEarlyTrafficSecret => b"CLIENT_EARLY_TRAFFIC_SECRET",
            Self::EarlyExporterSecret => b"EARLY_EXPORTER_SECRET",
            Self::ClientHandshakeTrafficSecret => b"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            Self::ServerHandshakeTrafficSecret => b"SERVER_HANDSHAKE_TRAFFIC_SECRET",
            Self::ClientTrafficSecret0 => b"CLIENT_TRAFFIC_SECRET_0",
            Self::ServerTrafficSecret0 => b"SERVER_TRAFFIC_SECRET_0",
            Self::ExporterSecret => b"EXPORTER_SECRET",
            Self::EchSecret => b"ECH_SECRET",
            Self::EchConfig => b"ECH_CONFIG",
        }
    }
}

/// Platform-selected RFC 9850 line-ending convention.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum LineEnding {
    /// Line feed.
    Lf,
    /// Carriage return followed by line feed.
    CrLf,
    /// Carriage return.
    Cr,
}

impl LineEnding {
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Lf => b"\n",
            Self::CrLf => b"\r\n",
            Self::Cr => b"\r",
        }
    }
}

/// A closed, value-free key-log encoding failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KeyLogError {
    /// A zero-length secret was rejected.
    EmptySecret,
    /// Exact line-length calculation overflowed `usize`.
    LengthOverflow,
    /// The caller buffer cannot contain the complete line.
    OutputTooSmall,
    /// A private post-preflight layout invariant failed.
    ContractInvariant,
}

fn checked_line_length(
    label: KeyLogLabel,
    secret_len: usize,
    ending: LineEnding,
) -> Result<usize, KeyLogError> {
    let secret_hex = secret_len
        .checked_mul(2)
        .ok_or(KeyLogError::LengthOverflow)?;
    label
        .as_bytes()
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(64))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(secret_hex))
        .and_then(|value| value.checked_add(ending.as_bytes().len()))
        .ok_or(KeyLogError::LengthOverflow)
}

fn take_prefix(output: &mut [u8], length: usize) -> Option<(&mut [u8], &mut [u8])> {
    output.split_at_mut_checked(length)
}

const fn hex_digit(value: u8) -> u8 {
    match value {
        0 => b'0',
        1 => b'1',
        2 => b'2',
        3 => b'3',
        4 => b'4',
        5 => b'5',
        6 => b'6',
        7 => b'7',
        8 => b'8',
        9 => b'9',
        10 => b'A',
        11 => b'B',
        12 => b'C',
        13 => b'D',
        14 => b'E',
        15 => b'F',
        _ => b'?',
    }
}

fn encode_hex(input: &[u8], output: &mut [u8]) {
    for (byte, pair) in input.iter().zip(output.chunks_exact_mut(2)) {
        let mut destinations = pair.iter_mut();
        if let Some(high) = destinations.next() {
            *high = hex_digit(*byte >> 4);
        }
        if let Some(low) = destinations.next() {
            *low = hex_digit(*byte & 0x0f);
        }
    }
}

/// Encodes one complete RFC 9850 line transactionally.
///
/// `client_random` is exactly the 32-byte ClientHello Random. The caller
/// chooses the applicable inner or outer value according to RFC 9850. All
/// length and capacity checks finish before the first output byte changes.
/// Successful output uses uppercase hexadecimal and exactly one ASCII space
/// between fields.
pub fn write_line<'a>(
    label: KeyLogLabel,
    client_random: &[u8; 32],
    secret: &[u8],
    ending: LineEnding,
    output: &'a mut [u8],
) -> Result<&'a [u8], KeyLogError> {
    if secret.is_empty() {
        return Err(KeyLogError::EmptySecret);
    }
    let needed = checked_line_length(label, secret.len(), ending)?;
    let line = output
        .get_mut(..needed)
        .ok_or(KeyLogError::OutputTooSmall)?;
    let (label_output, rest) =
        take_prefix(line, label.as_bytes().len()).ok_or(KeyLogError::ContractInvariant)?;
    let (first_space, rest) = take_prefix(rest, 1).ok_or(KeyLogError::ContractInvariant)?;
    let (random_output, rest) = take_prefix(rest, 64).ok_or(KeyLogError::ContractInvariant)?;
    let (second_space, rest) = take_prefix(rest, 1).ok_or(KeyLogError::ContractInvariant)?;
    let secret_hex_len = secret
        .len()
        .checked_mul(2)
        .ok_or(KeyLogError::LengthOverflow)?;
    let (secret_output, ending_output) =
        take_prefix(rest, secret_hex_len).ok_or(KeyLogError::ContractInvariant)?;
    if ending_output.len() != ending.as_bytes().len() {
        return Err(KeyLogError::ContractInvariant);
    }

    label_output.copy_from_slice(label.as_bytes());
    first_space.fill(b' ');
    encode_hex(client_random, random_output);
    second_space.fill(b' ');
    encode_hex(secret, secret_output);
    ending_output.copy_from_slice(ending.as_bytes());
    Ok(line)
}
