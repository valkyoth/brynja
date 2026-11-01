//! Consuming probes of real public owners, not copies of their implementations.
//! The observer may unwind after borrowing the live caller-backed secret owner.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(
    all(feature = "modern", feature = "legacy"),
    not(any(feature = "modern", feature = "legacy"))
))]
compile_error!("select exactly one HKDF owner family");

macro_rules! probe {
    ($name:ident, $owner:ty) => {
        #[inline(never)]
        pub fn $name(owner: $owner, observer: fn(&$owner)) {
            observer(&owner);
            drop(owner);
        }
    };
}

#[cfg(feature = "modern")]
mod modern {
    use brynja_crypto::hkdf::{
        DerivedKey, Prk, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
    };

    probe!(prk_sha224, Prk<'_, Sha224>);
    probe!(prk_sha256, Prk<'_, Sha256>);
    probe!(prk_sha384, Prk<'_, Sha384>);
    probe!(prk_sha512, Prk<'_, Sha512>);
    probe!(prk_sha512_224, Prk<'_, Sha512_224>);
    probe!(prk_sha512_256, Prk<'_, Sha512_256>);
    probe!(key_sha224, DerivedKey<'_, Sha224>);
    probe!(key_sha256, DerivedKey<'_, Sha256>);
    probe!(key_sha384, DerivedKey<'_, Sha384>);
    probe!(key_sha512, DerivedKey<'_, Sha512>);
    probe!(key_sha512_224, DerivedKey<'_, Sha512_224>);
    probe!(key_sha512_256, DerivedKey<'_, Sha512_256>);
}
#[cfg(feature = "modern")]
pub use modern::*;

#[cfg(feature = "legacy")]
mod legacy {
    use brynja_legacy_hkdf::{DerivedKey, Sha1Prk};

    probe!(prk_sha1, Sha1Prk<'_>);
    probe!(key_sha1, DerivedKey<'_>);
}
#[cfg(feature = "legacy")]
pub use legacy::*;
