use super::{Error, HardenedSha3SecretOutput, KeccakSession, Report, Sha3PublicDeclassification};
use crate::{Fips202BitString, Fips202Output};
mod core;
use core::{Borrowed, Scope, XofStorage};

macro_rules! xof {
    ($workspace:ident, $state:ident, $reader:ident, $rate:literal) => {
        /// Scoped sponge, CPU scratch, domain metadata and output stage.
        ///
        /// Secret inputs are accepted only after borrowing final storage in
        /// `with`/`with_bits`. The same authority is checked on every scope; no
        /// fallback or revival is available. Scope cleanup covers forgotten
        /// handles and recoverable unwind, not registers/spills or abort.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_execution::{Error, KeccakSession, in_place::", stringify!($workspace), "};\nuse brynja_crypto_cpu::static_execution::{Authority, Kernel};\nfn escape() -> Result<", stringify!($workspace), "<'static>, Error> { let a = Authority::new(Kernel::X86Keccak).map_err(Error::Backend)?; ", stringify!($workspace), "::new(KeccakSession::from_static(&a).map_err(Error::Backend)?) }\n```")]
        pub struct $workspace<'authority> { storage: XofStorage<'authority> }
        impl<'authority> $workspace<'authority> {
            /// Binds a validated static/hosted session before secret input.
            pub fn new(session: KeccakSession<'authority>) -> Result<Self, Error> {
                Ok(Self { storage: XofStorage::new(session, $rate)? })
            }
            /// Public backend/health metadata only; not accumulated lengths.
            #[must_use]
            pub fn report(&self) -> Report { self.storage.inner.engine.report() }
        }
        /// Exclusive absorbing handle; only its reference moves into a reader.
        #[must_use = "finalize or cancel the scoped state"]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        pub struct $state<'scope, 'authority> { inner: Borrowed<'scope, 'authority> }
        impl<'scope, 'authority> $state<'scope, 'authority> {
            /// Absorbs bytes; errors clear and terminally disable this computation.
            pub fn update(&mut self, input: &[u8]) -> Result<(), Error> { self.inner.update(input) }
            /// Transfers the same exclusive storage borrow to a reader.
            pub fn finalize_xof(self) -> Result<$reader<'scope, 'authority>, Error> {
                self.finalize_bits_xof(super::super::empty()?)
            }
            /// Includes canonical final input bits before transferring the borrow.
            pub fn finalize_bits_xof(mut self, input: Fips202BitString<'_>) -> Result<$reader<'scope, 'authority>, Error> {
                self.inner.finish(input)?;
                Ok($reader { inner: self.inner })
            }
            /// Consumes and clears without output.
            pub fn cancel(self) {}
        }
        /// Incremental reader borrowing the original sponge and staging storage.
        ///
        /// Any error clears and terminates it. Secret destinations clear on error;
        /// public destinations remain unchanged. Final-bit methods consume the
        /// reader. A separately borrowed secret output may outlive the scope.
        #[must_use = "read or cancel the scoped reader"]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        pub struct $reader<'scope, 'authority> { inner: Borrowed<'scope, 'authority> }
        impl $reader<'_, '_> {
            /// Arbitrary-length typed secret output; empty reads still check health.
            pub fn squeeze_secret<'out>(&mut self, output: &'out mut [u8]) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                self.inner.secret(output, None)
            }
            /// Transactional public output up to 168 bytes; explicit declassification.
            /// Larger output requires `squeeze_public_with_scratch`.
            pub fn squeeze_public(&mut self, output: &mut [u8], authority: Sha3PublicDeclassification) -> Result<(), Error> {
                self.inner.public(output, authority)
            }
            /// Arbitrary-length transactional public output. Scratch must cover
            /// output and is entirely cleared on every exit; it cannot alias output.
            pub fn squeeze_public_with_scratch(&mut self, output: &mut [u8], scratch: &mut [u8], authority: Sha3PublicDeclassification) -> Result<(), Error> {
                self.inner.public_with_scratch(output, scratch, authority)
            }
            /// Consumes the reader and returns canonical low-bit secret output.
            /// Empty output requires zero valid bits; nonempty requires 1..=8.
            /// Invalid shape clears the full destination and the computation.
            pub fn squeeze_final_bits_secret<'out>(mut self, output: &'out mut [u8], valid_bits: u8) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                self.inner.secret(output, Some(valid_bits))
            }
            /// Consumes the reader and declassifies canonical low-bit output.
            /// Scratch is fully cleared and failures preserve the public output.
            pub fn squeeze_final_bits_public(mut self, output: Fips202Output<'_>, scratch: &mut [u8], authority: Sha3PublicDeclassification) -> Result<(), Error> {
                let (bytes, valid) = output.into_parts();
                self.inner.public_with_scratch(bytes, scratch, authority)?;
                if valid != 0 && valid != 8 && let Some(last) = bytes.last_mut() {
                    brynja_core::apply_secret_byte_mask(last, u8::MAX >> 8_u8.saturating_sub(valid), 0);
                }
                Ok(())
            }
            /// Consumes and clears the original workspace storage.
            pub fn cancel(self) {}
        }
    };
}
macro_rules! shake {
    ($workspace:ident, $state:ident) => {
        impl<'authority> $workspace<'authority> {
            /// Starts a fresh borrowed SHAKE computation. Outer errors cover
            /// admission and skip the callback; they cannot clear captured buffers.
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), ";\nfn escape(w: &mut ", stringify!($workspace), "<'_>) { let state = w.with(|state| state); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), ";\nfn escape(w: &mut ", stringify!($workspace), "<'_>) { let reader = w.with(|state| state.finalize_xof()); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), ";\nfn overlap(w: &mut ", stringify!($workspace), "<'_>) { w.with(|_state| w.with(|_other| ())); }\n```")]
            pub fn with<R>(&mut self, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, Error> {
                self.storage.restart()?;
                let cleanup = Scope(&mut self.storage);
                Ok(operation($state { inner: Borrowed { storage: &mut *cleanup.0 } }))
            }
        }
    };
}
macro_rules! cshake {
    ($workspace:ident, $state:ident, $rate:literal) => {
        impl<'authority> $workspace<'authority> {
            /// Absorbs byte-oriented N/S only after borrowing final storage.
            /// The outer result covers admission/prefix setup and skips the
            /// callback on failure; it cannot clear captured output buffers.
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), ";\nfn escape(w: &mut ", stringify!($workspace), "<'_>) { let state = w.with(b\"\", b\"\", |state| state); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), ";\nfn escape(w: &mut ", stringify!($workspace), "<'_>) { let reader = w.with(b\"\", b\"\", |state| state.finalize_xof()); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), ";\nfn overlap(w: &mut ", stringify!($workspace), "<'_>) { w.with(b\"\", b\"\", |_state| w.with(b\"\", b\"\", |_other| ())); }\n```")]
            pub fn with<R>(&mut self, n: &[u8], s: &[u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, Error> {
                let n = Fips202BitString::new(n, if n.is_empty() { 0 } else { 8 }).map_err(|_| Error::PrefixEncoding)?;
                let s = Fips202BitString::new(s, if s.is_empty() { 0 } else { 8 }).map_err(|_| Error::PrefixEncoding)?;
                self.with_bits(n, s, operation)
            }
            /// Absorbs canonical bit-oriented N/S; empty N/S is exactly SHAKE.
            pub fn with_bits<R>(&mut self, n: Fips202BitString<'_>, s: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, Error> {
                self.storage.restart()?;
                let cleanup = Scope(&mut self.storage);
                cleanup.0.customize($rate, n, s)?;
                Ok(operation($state { inner: Borrowed { storage: &mut *cleanup.0 } }))
            }
        }
    };
}
xof!(Shake128Workspace, Shake128, Shake128Reader, 168);
xof!(Shake256Workspace, Shake256, Shake256Reader, 136);
xof!(Cshake128Workspace, Cshake128, Cshake128Reader, 168);
xof!(Cshake256Workspace, Cshake256, Cshake256Reader, 136);
shake!(Shake128Workspace, Shake128);
shake!(Shake256Workspace, Shake256);
cshake!(Cshake128Workspace, Cshake128, 168);
cshake!(Cshake256Workspace, Cshake256, 136);

#[cfg(test)]
mod tests;
