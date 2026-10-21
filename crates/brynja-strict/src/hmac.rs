//! Protected HMAC requests over SHA-2, general SHA-512/t and SHA-3.
//!
//! All sessions acquire GNU/Linux protected resources before accepting input;
//! unsupported platforms return errors, never portable or Mac-resident fallback.
//! Windows enclave HMAC is not implemented. Independent qualification is pending.
//! Original caller inputs/copies and fatal or OS-controlled paths remain outside
//! owned-memory clearing. Empty or predictable keys are not secure.
//!
//! [`Session`] always uses scalar hashing. This facade's `acceleration` feature
//! exposes a separate compiled session with explicit kernel selection and no
//! fallback. Enabling a lower-level feature elsewhere does not export that API.
//! Algorithm markers select concrete sealed implementations; low-level hash
//! traits, ordinary HMAC states, callbacks and CPU authorities are not exported.
//!
//! ```no_run
//! use brynja_strict::hmac::{Error, Limits, Session, Sha256, TagPolicy};
//! let mut session = Session::<Sha256>::new(TagPolicy::Full, Limits {
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_buffer_mapping_bytes: 65536, max_key_bytes: 4096,
//!     max_message_bits: 65536, max_chunks: 16,
//! })?;
//! let output = session.authenticate(&[0x42; 32], b"message")?;
//! assert_eq!(output.bit_len(), 256);
//! drop(output); // clears the retained loan; reuse keeps the same resources
//! # Ok::<(), Error>(())
//! ```
//!
//! No unprotected keyed owner or generic construction hook:
//! ```compile_fail
//! use brynja_strict::hmac::Hmac;
//! ```
//! ```compile_fail
//! use brynja_strict::hmac::Algorithm;
//! ```
//! ```compile_fail
//! use brynja_strict::hmac::Sha256;
//! let _ = Sha256::start();
//! ```
//! A retained output cannot outlive its session:
//! ```compile_fail
//! use brynja_strict::hmac::{Error, Output, Session, Sha256};
//! fn escape(session: &mut Session<Sha256>) -> Result<Output<'static, Sha256>, Error> {
//!     session.authenticate(b"key", b"message")
//! }
//! ```

pub use brynja_crypto_cpu_std::strict_hmac::{
    Bits, Cancellation, Error, Limits, Output, PublicDeclassification, Request, Session, Sha3_224,
    Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256, Sha512T,
    TagPolicy,
};

#[cfg(feature = "acceleration")]
pub use brynja_crypto_cpu_std::strict_hmac::{CompiledSession, Kernel};
