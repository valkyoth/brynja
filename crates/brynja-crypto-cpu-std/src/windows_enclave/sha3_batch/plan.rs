use super::{Algorithm, Error};

/// Public exact output shape. This is not a request to export confidential data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    algorithm: Algorithm,
    bytes: u16,
    last: u8,
}
impl Output {
    /// Fixed SHA-3 requires its exact byte width and last=8. SHAKE/cSHAKE accept
    /// at most 1024 bytes, last=1..=8; empty output requires last=0.
    pub fn new(algorithm: Algorithm, bytes: usize, last: u8) -> Result<Self, Error> {
        if bytes > 1024
            || last > 8
            || ((bytes == 0) != (last == 0))
            || algorithm.width().is_some_and(|n| n != bytes || last != 8)
        {
            return Err(Error::Bounds);
        }
        Ok(Self {
            algorithm,
            bytes: u16::try_from(bytes).map_err(|_| Error::Bounds)?,
            last,
        })
    }
    /// Declared public identity.
    #[must_use]
    pub fn algorithm(self) -> Algorithm {
        self.algorithm
    }
    /// Declared public output byte width, not an accumulated message length.
    #[must_use]
    pub fn bytes(self) -> usize {
        usize::from(self.bytes)
    }
    /// Number of meaningful low bits in the last byte; zero for empty output.
    #[must_use]
    pub fn last(self) -> u8 {
        self.last
    }
    fn wire(self) -> [u64; 3] {
        [
            self.algorithm.wire(),
            u64::from(self.bytes),
            u64::from(self.last),
        ]
    }
}
/// At least one active slot, with at most 1024 total retained output bytes.
/// `None` is inactive; an active zero-output XOF still requires completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub(super) slots: [Option<Output>; 8],
    width: usize,
}
impl Plan {
    /// Outputs are packed in slot order; inactive slots occupy no bytes.
    pub fn new(slots: [Option<Output>; 8]) -> Result<Self, Error> {
        let width = slots
            .iter()
            .flatten()
            .try_fold(0_usize, |n, s| n.checked_add(s.bytes()))
            .ok_or(Error::Bounds)?;
        if slots.iter().all(Option::is_none) || width > 1024 {
            return Err(Error::Bounds);
        }
        Ok(Self { slots, width })
    }
    /// Public shapes, not message metadata or private intermediate state.
    #[must_use]
    pub fn slots(self) -> [Option<Output>; 8] {
        self.slots
    }
    /// Length of the populated prefix in the fixed 1024-byte export buffer.
    #[must_use]
    pub fn output_bytes(self) -> usize {
        self.width
    }
    pub(super) fn wire(self) -> [[u64; 3]; 8] {
        self.slots.map(|s| s.map_or([0; 3], Output::wire))
    }
}
