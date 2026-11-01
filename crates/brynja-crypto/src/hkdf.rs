//! Portable HKDF over explicitly admitted modern SHA-2 HMAC identities.
//!
//! Implements RFC 5869 Extract/Expand and RFC 8446 section 7.1 label framing.
//! This development implementation has not completed HKDF-specific security
//! review, compiler qualification or lifecycle/proof assessments. Existing
//! HMAC evidence is not evidence of this composition. No legacy hash, SHA-3,
//! arbitrary digest plug-in, implicit hash selection or CPU backend is admitted.
//!
//! PRKs and output use caller-backed clearing owners, without allocation.
//! Caller copies, forgotten owners, compiler spills/moves, paging, aborts and
//! process termination are outside Drop-based cleanup. This is not protected
//! memory. Protocols remain responsible for input entropy and domain separation;
//! HKDF is not password hashing. TLS labels do not implement a TLS key schedule.

#![forbid(unsafe_code)]

mod derive;
pub use brynja_mac_hmac::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
pub use derive::{Algorithm, DerivedKey, Error, Prk};

mod parameters;
pub use parameters::{ExpansionLength, ParameterError, Tls13Label};
