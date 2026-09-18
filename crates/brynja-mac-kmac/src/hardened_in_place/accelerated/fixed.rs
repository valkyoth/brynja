use super::backend::Backend;
use super::*;

macro_rules! fixed {
    ($workspace:ident, $state:ident, $storage:ident, $backend:ident, $rate:literal, $strength:literal) => {
        /// Caller-owned accelerated KMAC sponge, scratch and erasing verification storage.
        /// No secrets are accepted until the workspace is exclusively borrowed.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        pub struct $workspace<'authority> {
            sponge: cshake::$storage<'authority>,
            stage: [u8; 168],
            metadata: Metadata,
        }
        impl<'authority> $workspace<'authority> {
            /// Binds the supplied authority before accepting secret input.
            pub fn new(session: KeccakSession<'authority>) -> Result<Self, KmacError> {
                Ok(Self { sponge: cshake::$storage::new(session)?, metadata: Metadata::new(), stage: [0; 168] })
            }
            /// Non-authorizing backend/health metadata, never secret lengths.
            #[must_use]
            pub fn report(&self) -> Report { self.sponge.report() }
            /// Production byte-key scope. Setup failure skips the callback.
            #[doc = concat!("```compile_fail\nuse brynja_mac_kmac::execution::in_place::", stringify!($workspace), ";\nfn escape(w: &mut ", stringify!($workspace), "<'_>) { let state = w.with(&[0;32], b\"\", |state| state); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_mac_kmac::execution::in_place::", stringify!($workspace), ";\nfn overlap(w: &mut ", stringify!($workspace), "<'_>) { w.with(&[0;32], b\"\", |_| w.with(&[0;32], b\"\", |_| ())); }\n```")]
            pub fn with<R>(
                &mut self,
                key: &[u8],
                customization: &[u8],
                operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R,
            ) -> Result<R, KmacError> {
                self.with_bits(bytes(key)?, bytes(customization)?, operation)
            }
            /// Production canonical-bit scope; keys must meet the selected strength.
            pub fn with_bits<R>(
                &mut self,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
                operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R,
            ) -> Result<R, KmacError> {
                if key.bit_len() < $strength {
                    return Err(KmacError::KeyTooShort);
                }
                self.scope(key, customization, operation)
            }
            /// Exact-conformance byte-key scope, including empty/short keys.
            #[cfg(feature = "conformance-testing")]
            pub fn with_conformance<R>(
                &mut self,
                key: &[u8],
                customization: &[u8],
                operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R,
            ) -> Result<R, KmacError> {
                self.with_bits_conformance(bytes(key)?, bytes(customization)?, operation)
            }
            /// Exact-conformance canonical-bit scope. Production finalizers still
            /// enforce key/tag strength; weak results require conformance methods.
            #[cfg(feature = "conformance-testing")]
            pub fn with_bits_conformance<R>(
                &mut self,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
                operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R,
            ) -> Result<R, KmacError> {
                self.scope(key, customization, operation)
            }
            /// Production scope with arbitrary-width public-tag staging.
            /// Scratch is entirely cleared on every exit, including short-key rejection.
            pub fn with_scratch<R>(&mut self, key: &[u8], customization: &[u8], scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, KmacError> {
                let scratch = Scratch(scratch);
                self.with_bits_and_scratch(bytes(key)?, bytes(customization)?, scratch.0, operation)
            }
            /// Canonical-bit production scope with caller-provided staging.
            pub fn with_bits_and_scratch<R>(&mut self, key: Fips202BitString<'_>, customization: Fips202BitString<'_>, scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, KmacError> {
                let scratch = Scratch(scratch);
                if key.bit_len() < $strength { return Err(KmacError::KeyTooShort); }
                Self::run_scope(&mut self.sponge, &mut self.metadata, scratch.0, key, customization, operation)
            }
            /// Exact-conformance bit scope with arbitrary-width public staging.
            #[cfg(feature = "conformance-testing")]
            pub fn with_bits_and_scratch_conformance<R>(&mut self, key: Fips202BitString<'_>, customization: Fips202BitString<'_>, scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, KmacError> {
                Self::run_scope(&mut self.sponge, &mut self.metadata, scratch, key, customization, operation)
            }
            fn scope<R>(
                &mut self,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
                operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R,
            ) -> Result<R, KmacError> {
                Self::run_scope(&mut self.sponge, &mut self.metadata, &mut self.stage, key, customization, operation)
            }
            fn run_scope<R>(sponge: &mut cshake::$storage<'authority>, metadata: &mut Metadata, scratch: &mut [u8], key: Fips202BitString<'_>, customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, KmacError> {
                metadata.wipe();
                let cleanup = Guard(metadata);
                let scratch = Scratch(scratch);
                sponge
                    .with_bits(bytes(b"KMAC")?, customization, |state| {
                        let core = Core::new(Backend { state, scratch: &mut *scratch.0 }, &mut *cleanup.0, key, $rate, $strength)?;
                        Ok(operation($state { core }))
                    })
                    .map_err(KmacError::from)?
            }
        }
        /// Exclusive KMAC handle. Finalization consumes only borrowed handles,
        /// not the sponge owner. Update errors clear and terminate the computation.
        /// No message-length or preflight query is exposed.
        #[must_use = "finalize or cancel the scoped KMAC state"]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        pub struct $state<'scope, 'authority> {
            pub(super) core: Core<'scope, Backend<cshake::$backend<'scope, 'authority>, &'scope mut [u8]>>,
        }
        impl $state<'_, '_> {
            /// Reports key-strength classification, not exact key length.
            #[must_use]
            pub fn key_policy(&self) -> KmacKeyPolicy {
                self.core.key_policy()
            }
            /// Always non-approved; this is not a FIPS validation claim.
            #[must_use]
            pub const fn service_status(&self) -> KmacServiceStatus {
                KmacServiceStatus::NonApproved
            }
            /// Absorbs bytes; any failure clears and disables this computation.
            pub fn update(&mut self, input: &[u8]) -> Result<(), KmacError> {
                self.core.update(input)
            }
            /// Full-strength public tag; errors preserve output. The scope's staging
            /// must cover the entire tag (168 bytes with ordinary `with`).
            pub fn finalize_tag<'out>(
                self,
                output: &'out mut [u8],
            ) -> Result<KmacTag<'out>, KmacError> {
                let valid = byte_valid(output.len());
                self.core.tag(None, output, valid, $strength, true)
            }
            /// Produces a full-strength canonical-bit public tag.
            pub fn finalize_tag_bits<'out>(
                self,
                input: Fips202BitString<'_>,
                output: &'out mut [u8],
                valid: u8,
            ) -> Result<KmacTag<'out>, KmacError> {
                self.core.tag(Some(input), output, valid, $strength, true)
            }
            /// Full-strength secret output; every failure clears the destination.
            pub fn finalize_secret<'out>(
                self,
                output: &'out mut [u8],
            ) -> Result<KmacSecretOutput<'out>, KmacError> {
                let valid = byte_valid(output.len());
                self.core.secret(None, output, valid, $strength, true)
            }
            /// Full-strength canonical-bit secret output, never implicitly public.
            pub fn finalize_secret_bits<'out>(
                self,
                input: Fips202BitString<'_>,
                output: &'out mut [u8],
                valid: u8,
            ) -> Result<KmacSecretOutput<'out>, KmacError> {
                self.core
                    .secret(Some(input), output, valid, $strength, true)
            }
            /// Verifies at the candidate's public length. Use verify_exact when
            /// the application mandates one exact tag length.
            pub fn verify(self, candidate: &[u8]) -> Result<KmacVerification, KmacError> {
                self.core
                    .verify(None, bytes(candidate)?, None, $strength, true)
            }
            /// Verifies a canonical-bit tag after final message bits.
            pub fn verify_bits(
                self,
                input: Fips202BitString<'_>,
                candidate: Fips202BitString<'_>,
            ) -> Result<KmacVerification, KmacError> {
                self.core
                    .verify(Some(input), candidate, None, $strength, true)
            }
            /// Binds verification to an application-specified public bit length.
            pub fn verify_exact(
                self,
                input: Fips202BitString<'_>,
                candidate: Fips202BitString<'_>,
                expected_bits: u128,
            ) -> Result<KmacVerification, KmacError> {
                self.core
                    .verify(Some(input), candidate, Some(expected_bits), $strength, true)
            }
            /// Produces a standards-valid public tag, even below production strength.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_tag_conformance<'out>(
                self,
                output: &'out mut [u8],
            ) -> Result<KmacTag<'out>, KmacError> {
                let valid = byte_valid(output.len());
                self.core.tag(None, output, valid, $strength, false)
            }
            /// Exact-conformance canonical-bit public tag.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_tag_bits_conformance<'out>(
                self,
                input: Fips202BitString<'_>,
                output: &'out mut [u8],
                valid: u8,
            ) -> Result<KmacTag<'out>, KmacError> {
                self.core.tag(Some(input), output, valid, $strength, false)
            }
            /// Exact-conformance byte secret output.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_secret_conformance<'out>(
                self,
                output: &'out mut [u8],
            ) -> Result<KmacSecretOutput<'out>, KmacError> {
                let valid = byte_valid(output.len());
                self.core.secret(None, output, valid, $strength, false)
            }
            /// Exact-conformance canonical-bit secret output.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_secret_bits_conformance<'out>(
                self,
                input: Fips202BitString<'_>,
                output: &'out mut [u8],
                valid: u8,
            ) -> Result<KmacSecretOutput<'out>, KmacError> {
                self.core
                    .secret(Some(input), output, valid, $strength, false)
            }
            /// Exact-conformance byte verification, including weak tag lengths.
            #[cfg(feature = "conformance-testing")]
            pub fn verify_conformance(
                self,
                candidate: &[u8],
            ) -> Result<KmacVerification, KmacError> {
                self.core
                    .verify(None, bytes(candidate)?, None, $strength, false)
            }
            /// Exact-conformance canonical-bit verification.
            #[cfg(feature = "conformance-testing")]
            pub fn verify_bits_conformance(
                self,
                input: Fips202BitString<'_>,
                candidate: Fips202BitString<'_>,
            ) -> Result<KmacVerification, KmacError> {
                self.core
                    .verify(Some(input), candidate, None, $strength, false)
            }
            /// Consumes and clears without producing output.
            pub fn cancel(self) {}
        }
    };
}
fixed!(
    Kmac128Workspace,
    Kmac128,
    Cshake128Workspace,
    Cshake128,
    168,
    128
);
fixed!(
    Kmac256Workspace,
    Kmac256,
    Cshake256Workspace,
    Cshake256,
    136,
    256
);
