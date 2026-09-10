//! Opt-in complete SHA-2 hashing of public data through operational kernels.
//!
//! Default hash APIs remain portable. These consuming stream owners retain one
//! selected route, including padding compression. No secret-state erasure is
//! provided: use the separate hardened APIs for confidential data. A backend
//! error never permits fallback. No global installation, allocation or probing.
//!
//! ```
//! use brynja_hash_sha2::execution::{Execution, Sha256};
//! let result = Sha256::hash(Execution::portable(), b"abc").unwrap();
//! assert_eq!(result.report.message_blocks, 0);
//! assert_eq!(result.report.padding_blocks, 1);
//! ```
//! ```compile_fail,E0382
//! use brynja_hash_sha2::execution::{Execution, Sha256};
//! let mut stream = Sha256::new(Execution::portable()).unwrap();
//! let _ = stream.finalize();
//! stream.update(b"too late").unwrap();
//! ```
//! ```compile_fail,E0277
//! fn send<T: Send>() {}
//! send::<brynja_hash_sha2::execution::Sha256<'static>>();
//! ```
//! ```compile_fail,E0061
//! use brynja_hash_sha2::{HardenedSha256, execution::Execution};
//! let _ = HardenedSha256::new(Execution::portable());
//! ```

mod engine;
#[cfg(feature = "general-sha512-t")]
mod general;
mod named;
mod route;

pub use brynja_crypto_cpu::static_execution::{Kernel, PublicData};
pub(crate) use engine::impl_engine;
#[cfg(feature = "general-sha512-t")]
pub use general::Sha512T;
pub use named::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
pub use route::{Execution, Mode, Route, StaticSelection};

/// A rejected ordinary hash operation. No fallback follows a backend error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The complete message or its accounting exceeds the algorithm domain.
    MessageTooLong,
    /// Kernel selection, startup health, operation or generation failed.
    Backend(brynja_crypto_cpu::static_execution::Error),
    /// General-t digest rendering rejected its canonical output.
    #[cfg(feature = "general-sha512-t")]
    Digest(crate::Sha512TError),
}

impl From<brynja_crypto_cpu::static_execution::Error> for Error {
    fn from(error: brynja_crypto_cpu::static_execution::Error) -> Self {
        Self::Backend(error)
    }
}

/// Actual successful work of one stream; not independent verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Immutable selected route, including any static unavailability reason.
    pub route: Route,
    /// Complete message blocks compressed on this route.
    pub message_blocks: u128,
    /// Padding blocks compressed on this route (one or two at finalization).
    pub padding_blocks: u128,
    /// Portable IV-derivation compression blocks (one for general-t).
    pub portable_iv_blocks: u128,
}

impl Report {
    fn new(route: Route, portable_iv_blocks: u128) -> Self {
        Self {
            route,
            message_blocks: 0,
            padding_blocks: 0,
            portable_iv_blocks,
        }
    }

    pub(crate) fn count(&mut self, padding: bool) -> Result<(), Error> {
        let count = if padding {
            &mut self.padding_blocks
        } else {
            &mut self.message_blocks
        };
        *count = count.checked_add(1).ok_or(Error::MessageTooLong)?;
        Ok(())
    }
}

/// Public digest and successful execution report. Not a secret output owner.
pub struct Output<D> {
    /// Exact algorithm-specific public digest.
    pub digest: D,
    /// Actual compression route and successful work counts.
    pub report: Report,
}
