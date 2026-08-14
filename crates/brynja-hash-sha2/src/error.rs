/// A closed SHA-256 input failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha256Error {
    /// Accepting the update would reach or exceed 2^64 message bits.
    MessageTooLong,
}
