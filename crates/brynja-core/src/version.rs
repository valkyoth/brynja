//! Protocol-version identities used by shared value domains.

/// A protocol family with distinct stream and datagram behavior.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProtocolFamily {
    /// The TLS stream protocol family.
    Tls,
    /// The DTLS datagram protocol family.
    Dtls,
}

/// A concrete modern protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProtocolVersion {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
    /// DTLS 1.2.
    Dtls12,
    /// DTLS 1.3.
    Dtls13,
}

impl ProtocolVersion {
    /// Returns the protocol family.
    #[must_use]
    pub const fn family(self) -> ProtocolFamily {
        match self {
            Self::Tls12 | Self::Tls13 => ProtocolFamily::Tls,
            Self::Dtls12 | Self::Dtls13 => ProtocolFamily::Dtls,
        }
    }

    /// Reports whether this is a 1.3-generation protocol.
    #[must_use]
    pub const fn is_13(self) -> bool {
        matches!(self, Self::Tls13 | Self::Dtls13)
    }
}
