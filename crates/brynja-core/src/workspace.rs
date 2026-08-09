//! Exact caller-owned workspace partitioning and bounded arena allocation.

use crate::{
    ArenaDomain, ArenaKind, CertificateDomain, OutputDomain, PlaintextDomain, SecretDomain,
    TranscriptDomain,
};
use core::marker::PhantomData;

/// A closed, value-free workspace construction failure.
///
/// The error never carries capacities, offsets, allocation counts, or bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum WorkspaceError {
    /// An arena length was assigned more than once.
    Duplicate(ArenaKind),
    /// An arena had no explicit length assignment.
    Incomplete(ArenaKind),
    /// Summing the five arena lengths overflowed `usize`.
    LengthOverflow,
    /// The backing slice length did not exactly match the layout.
    CapacityMismatch,
}

/// A closed, value-free arena allocation failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ArenaError {
    /// Computing the requested end or accounting increment overflowed `usize`.
    LengthOverflow,
    /// The complete requested allocation was not available.
    InsufficientCapacity,
}

/// An exact five-domain workspace layout.
///
/// The layout deliberately requires every domain and does not implement
/// `Debug` or `Display`, keeping configured resource values out of accidental
/// diagnostics. Empty arenas are valid. Their boundary addresses may be equal,
/// but empty ranges contain no bytes and therefore do not overlap.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct WorkspaceLayout {
    secret: usize,
    plaintext: usize,
    transcript: usize,
    certificate: usize,
    output: usize,
    total: usize,
}

impl WorkspaceLayout {
    /// Starts an empty, named, single-assignment layout builder.
    pub const fn builder() -> WorkspaceLayoutBuilder {
        WorkspaceLayoutBuilder::new()
    }

    /// Returns the byte capacity assigned to one arena.
    pub const fn arena_bytes(&self, kind: ArenaKind) -> usize {
        match kind {
            ArenaKind::Secret => self.secret,
            ArenaKind::Plaintext => self.plaintext,
            ArenaKind::Transcript => self.transcript,
            ArenaKind::Certificate => self.certificate,
            ArenaKind::Output => self.output,
        }
    }

    /// Returns the exact required backing-slice length.
    pub const fn total_bytes(&self) -> usize {
        self.total
    }
}

/// A named, fail-closed builder for [`WorkspaceLayout`].
///
/// Every arena must be assigned exactly once. Named setters prevent positional
/// transposition, and [`Self::build`] checks the complete length before a
/// workspace can borrow storage.
#[must_use = "the builder must be completed with WorkspaceLayoutBuilder::build"]
pub struct WorkspaceLayoutBuilder {
    secret: Option<usize>,
    plaintext: Option<usize>,
    transcript: Option<usize>,
    certificate: Option<usize>,
    output: Option<usize>,
}

impl WorkspaceLayoutBuilder {
    const EMPTY: Self = Self {
        secret: None,
        plaintext: None,
        transcript: None,
        certificate: None,
        output: None,
    };

    /// Creates a builder with every arena unassigned.
    pub const fn new() -> Self {
        Self::EMPTY
    }

    /// Assigns the secret-arena capacity.
    pub const fn secret_bytes(mut self, bytes: usize) -> Result<Self, WorkspaceError> {
        if self.secret.is_some() {
            Err(WorkspaceError::Duplicate(ArenaKind::Secret))
        } else {
            self.secret = Some(bytes);
            Ok(self)
        }
    }

    /// Assigns the plaintext-arena capacity.
    pub const fn plaintext_bytes(mut self, bytes: usize) -> Result<Self, WorkspaceError> {
        if self.plaintext.is_some() {
            Err(WorkspaceError::Duplicate(ArenaKind::Plaintext))
        } else {
            self.plaintext = Some(bytes);
            Ok(self)
        }
    }

    /// Assigns the transcript-arena capacity.
    pub const fn transcript_bytes(mut self, bytes: usize) -> Result<Self, WorkspaceError> {
        if self.transcript.is_some() {
            Err(WorkspaceError::Duplicate(ArenaKind::Transcript))
        } else {
            self.transcript = Some(bytes);
            Ok(self)
        }
    }

    /// Assigns the certificate-arena capacity.
    pub const fn certificate_bytes(mut self, bytes: usize) -> Result<Self, WorkspaceError> {
        if self.certificate.is_some() {
            Err(WorkspaceError::Duplicate(ArenaKind::Certificate))
        } else {
            self.certificate = Some(bytes);
            Ok(self)
        }
    }

    /// Assigns the output-arena capacity.
    pub const fn output_bytes(mut self, bytes: usize) -> Result<Self, WorkspaceError> {
        if self.output.is_some() {
            Err(WorkspaceError::Duplicate(ArenaKind::Output))
        } else {
            self.output = Some(bytes);
            Ok(self)
        }
    }

    /// Builds a layout after checking presence and aggregate length.
    pub const fn build(self) -> Result<WorkspaceLayout, WorkspaceError> {
        let secret = match self.secret {
            Some(bytes) => bytes,
            None => return Err(WorkspaceError::Incomplete(ArenaKind::Secret)),
        };
        let plaintext = match self.plaintext {
            Some(bytes) => bytes,
            None => return Err(WorkspaceError::Incomplete(ArenaKind::Plaintext)),
        };
        let transcript = match self.transcript {
            Some(bytes) => bytes,
            None => return Err(WorkspaceError::Incomplete(ArenaKind::Transcript)),
        };
        let certificate = match self.certificate {
            Some(bytes) => bytes,
            None => return Err(WorkspaceError::Incomplete(ArenaKind::Certificate)),
        };
        let output = match self.output {
            Some(bytes) => bytes,
            None => return Err(WorkspaceError::Incomplete(ArenaKind::Output)),
        };
        let total = match secret.checked_add(plaintext) {
            Some(total) => total,
            None => return Err(WorkspaceError::LengthOverflow),
        };
        let total = match total.checked_add(transcript) {
            Some(total) => total,
            None => return Err(WorkspaceError::LengthOverflow),
        };
        let total = match total.checked_add(certificate) {
            Some(total) => total,
            None => return Err(WorkspaceError::LengthOverflow),
        };
        let total = match total.checked_add(output) {
            Some(total) => total,
            None => return Err(WorkspaceError::LengthOverflow),
        };
        Ok(WorkspaceLayout {
            secret,
            plaintext,
            transcript,
            certificate,
            output,
            total,
        })
    }
}

impl Default for WorkspaceLayoutBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// One monotonic, caller-owned workspace arena.
///
/// Successful non-empty allocations are disjoint and advance the arena once.
/// Empty allocations succeed without affecting accounting. Failed allocations
/// change neither bytes nor counters. The arena deliberately cannot release or
/// rewind storage, so a later allocation cannot alias an earlier one.
///
/// This type does not implement `Clone`, `Copy`, `Debug`, or `Display`. It does
/// not own secrets and makes no erasure guarantee; secret destruction is a
/// separate lifecycle contract. In particular, [`SecretDomain`] is only a
/// compile-time storage classification in this release. It does not authorize
/// sensitive use before the future initialization, lifetime, and proven
/// zeroization contracts are implemented.
#[must_use = "arena accounting must remain live while its allocations are used"]
pub struct Arena<'storage, Domain: ArenaDomain> {
    storage: &'storage mut [u8],
    position: usize,
    high_water: usize,
    allocation_count: usize,
    domain: PhantomData<Domain>,
}

impl<'storage, Domain: ArenaDomain> Arena<'storage, Domain> {
    const fn new(storage: &'storage mut [u8]) -> Self {
        Self {
            storage,
            position: 0,
            high_water: 0,
            allocation_count: 0,
            domain: PhantomData,
        }
    }

    /// Returns this arena's storage domain.
    pub const fn kind(&self) -> ArenaKind {
        Domain::KIND
    }

    /// Returns the arena's fixed capacity.
    pub const fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Returns the bytes admitted by successful non-empty allocations.
    pub const fn used(&self) -> usize {
        self.position
    }

    /// Returns the unallocated capacity.
    pub const fn remaining(&self) -> usize {
        debug_assert!(self.position <= self.storage.len());
        self.storage.len().saturating_sub(self.position)
    }

    /// Returns the greatest successfully admitted end offset.
    pub const fn high_water(&self) -> usize {
        self.high_water
    }

    /// Returns the number of successful non-empty allocations.
    pub const fn allocation_count(&self) -> usize {
        self.allocation_count
    }

    /// Allocates one complete, disjoint byte range.
    ///
    /// The returned bytes retain their previous contents. A caller must
    /// initialize the complete range before reading it. Debug canaries cannot
    /// prove that property, so future secret-bearing consumers require a typed
    /// complete-initialization transition and error-route tests. Overflow or
    /// exhaustion leaves all arena accounting and storage unchanged.
    pub fn allocate(&mut self, length: usize) -> Result<&mut [u8], ArenaError> {
        let end = match self.position.checked_add(length) {
            Some(end) => end,
            None => return Err(ArenaError::LengthOverflow),
        };
        if end > self.storage.len() {
            return Err(ArenaError::InsufficientCapacity);
        }
        let next_count = if length == 0 {
            self.allocation_count
        } else {
            debug_assert!(self.allocation_count < end);
            match self.allocation_count.checked_add(1) {
                Some(count) => count,
                None => return Err(ArenaError::LengthOverflow),
            }
        };
        debug_assert!(self.storage.get(self.position..end).is_some());
        let bytes = match self.storage.get_mut(self.position..end) {
            Some(bytes) => bytes,
            None => return Err(ArenaError::InsufficientCapacity),
        };
        self.position = end;
        self.high_water = end;
        self.allocation_count = next_count;
        Ok(bytes)
    }
}

/// An exact, allocation-free partition of one caller-owned mutable slice.
///
/// Construction succeeds only when the backing length exactly equals the
/// layout total. The slice is then safely split, in [`ArenaKind::ALL`] order,
/// into five byte-disjoint arenas. Independent buffers are deliberately not
/// accepted, eliminating an alias/overlap decision from callers.
///
/// ```compile_fail
/// let layout = brynja_core::WorkspaceLayout::builder()
///     .secret_bytes(1)?.plaintext_bytes(1)?.transcript_bytes(1)?
///     .certificate_bytes(1)?.output_bytes(1)?.build()?;
/// let mut storage = [0_u8; 5];
/// let workspace = brynja_core::Workspace::new(&mut storage, layout)?;
/// storage.fill(7);
/// drop(workspace);
/// # Ok::<(), brynja_core::WorkspaceError>(())
/// ```
///
/// ```compile_fail
/// let layout = brynja_core::WorkspaceLayout::builder()
///     .secret_bytes(0)?.plaintext_bytes(0)?.transcript_bytes(0)?
///     .certificate_bytes(0)?.output_bytes(0)?.build()?;
/// let mut storage = [];
/// let workspace = brynja_core::Workspace::new(&mut storage, layout)?;
/// println!("{workspace:?}");
/// # Ok::<(), brynja_core::WorkspaceError>(())
/// ```
#[must_use = "workspace accounting must remain live while its arenas are used"]
pub struct Workspace<'storage> {
    secret: Arena<'storage, SecretDomain>,
    plaintext: Arena<'storage, PlaintextDomain>,
    transcript: Arena<'storage, TranscriptDomain>,
    certificate: Arena<'storage, CertificateDomain>,
    output: Arena<'storage, OutputDomain>,
}

/// Simultaneous named borrows of all five workspace arenas.
///
/// Public field names keep domain selection explicit while Rust enforces that
/// the five mutable arena borrows cannot alias. Their sealed compile-time
/// marker types also prevent one named field from being swapped with another.
///
/// ```compile_fail
/// fn swap_domains(arenas: &mut brynja_core::WorkspaceArenas<'_, '_>) {
///     core::mem::swap(&mut arenas.secret, &mut arenas.output);
/// }
/// ```
#[must_use = "the named arena borrows must be used before the workspace"]
pub struct WorkspaceArenas<'workspace, 'storage> {
    /// The secret arena.
    pub secret: &'workspace mut Arena<'storage, SecretDomain>,
    /// The plaintext arena.
    pub plaintext: &'workspace mut Arena<'storage, PlaintextDomain>,
    /// The transcript arena.
    pub transcript: &'workspace mut Arena<'storage, TranscriptDomain>,
    /// The certificate arena.
    pub certificate: &'workspace mut Arena<'storage, CertificateDomain>,
    /// The output arena.
    pub output: &'workspace mut Arena<'storage, OutputDomain>,
}

impl<'storage> Workspace<'storage> {
    /// Partitions an exact-size caller-owned backing slice without mutation.
    pub fn new(
        storage: &'storage mut [u8],
        layout: WorkspaceLayout,
    ) -> Result<Self, WorkspaceError> {
        if storage.len() != layout.total_bytes() {
            return Err(WorkspaceError::CapacityMismatch);
        }
        let (secret, remaining) = split_prefix(storage, layout.secret)?;
        let (plaintext, remaining) = split_prefix(remaining, layout.plaintext)?;
        let (transcript, remaining) = split_prefix(remaining, layout.transcript)?;
        let (certificate, remaining) = split_prefix(remaining, layout.certificate)?;
        let (output, remaining) = split_prefix(remaining, layout.output)?;
        debug_assert!(remaining.is_empty());
        Ok(Self {
            secret: Arena::new(secret),
            plaintext: Arena::new(plaintext),
            transcript: Arena::new(transcript),
            certificate: Arena::new(certificate),
            output: Arena::new(output),
        })
    }

    /// Borrows the secret arena.
    pub const fn secret(&mut self) -> &mut Arena<'storage, SecretDomain> {
        &mut self.secret
    }

    /// Borrows the plaintext arena.
    pub const fn plaintext(&mut self) -> &mut Arena<'storage, PlaintextDomain> {
        &mut self.plaintext
    }

    /// Borrows the transcript arena.
    pub const fn transcript(&mut self) -> &mut Arena<'storage, TranscriptDomain> {
        &mut self.transcript
    }

    /// Borrows the certificate arena.
    pub const fn certificate(&mut self) -> &mut Arena<'storage, CertificateDomain> {
        &mut self.certificate
    }

    /// Borrows the output arena.
    pub const fn output(&mut self) -> &mut Arena<'storage, OutputDomain> {
        &mut self.output
    }

    /// Borrows all five structurally disjoint arenas at once.
    pub const fn arenas_mut(&mut self) -> WorkspaceArenas<'_, 'storage> {
        WorkspaceArenas {
            secret: &mut self.secret,
            plaintext: &mut self.plaintext,
            transcript: &mut self.transcript,
            certificate: &mut self.certificate,
            output: &mut self.output,
        }
    }
}

fn split_prefix(
    storage: &mut [u8],
    length: usize,
) -> Result<(&mut [u8], &mut [u8]), WorkspaceError> {
    debug_assert!(length <= storage.len());
    match storage.split_at_mut_checked(length) {
        Some(parts) => Ok(parts),
        None => Err(WorkspaceError::CapacityMismatch),
    }
}
