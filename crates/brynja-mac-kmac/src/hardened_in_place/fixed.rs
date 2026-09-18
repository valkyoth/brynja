use super::core_state::{Core, Guard, Metadata, byte_valid, bytes};
use crate::{
    Fips202BitString, KmacError, KmacKeyPolicy, KmacSecretOutput, KmacServiceStatus, KmacTag,
    KmacVerification,
};
use brynja_hash_sha3::hardened_in_place as cshake;

macro_rules! fixed {
    ($workspace:ident, $state:ident, $storage:ident, $backend:ident, $rate:literal, $strength:literal) => {
        /// Caller-owned portable KMAC sponge and erasing verification storage.
        /// No secrets are accepted until the workspace is exclusively borrowed.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_mac_kmac::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_mac_kmac::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_mac_kmac::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_mac_kmac::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_mac_kmac::hardened_in_place::", stringify!($workspace), ">();\n```")]
        pub struct $workspace {
            sponge: cshake::$storage,
            metadata: Metadata,
        }
        impl Default for $workspace {
            fn default() -> Self {
                Self::new()
            }
        }
        impl $workspace {
            #[cfg(test)]
            pub(super) fn metadata_cleared(&self) -> bool { self.metadata.cleared() }
            /// Constructs secret-free storage. No hardware route is selected.
            #[must_use]
            pub fn new() -> Self {
                Self {
                    sponge: cshake::$storage::new(),
                    metadata: Metadata::new(),
                }
            }
            /// Production byte-key scope. Setup failure skips the callback.
            #[doc = concat!("```compile_fail\nuse brynja_mac_kmac::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nlet state = w.with(&[0;32], b\"\", |state| state);\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_mac_kmac::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nw.with(&[0;32], b\"\", |_state| w.with(&[0;32], b\"\", |_| ()));\n```")]
            pub fn with<R>(
                &mut self,
                key: &[u8],
                customization: &[u8],
                operation: impl for<'scope> FnOnce($state<'scope>) -> R,
            ) -> Result<R, KmacError> {
                self.with_bits(bytes(key)?, bytes(customization)?, operation)
            }
            /// Production canonical-bit scope; keys must meet the selected strength.
            pub fn with_bits<R>(
                &mut self,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
                operation: impl for<'scope> FnOnce($state<'scope>) -> R,
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
                operation: impl for<'scope> FnOnce($state<'scope>) -> R,
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
                operation: impl for<'scope> FnOnce($state<'scope>) -> R,
            ) -> Result<R, KmacError> {
                self.scope(key, customization, operation)
            }
            fn scope<R>(
                &mut self,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
                operation: impl for<'scope> FnOnce($state<'scope>) -> R,
            ) -> Result<R, KmacError> {
                self.metadata.wipe();
                let cleanup = Guard(&mut self.metadata);
                self.sponge
                    .with_bits(bytes(b"KMAC")?, customization, |state| {
                        let core = Core::new(state, &mut *cleanup.0, key, $rate, $strength)?;
                        Ok(operation($state { core }))
                    })
                    .map_err(KmacError::from)?
            }
        }
        /// Exclusive KMAC handle. Finalization consumes only borrowed handles,
        /// not the sponge owner. Update errors clear and terminate the computation.
        /// No message-length or preflight query is exposed.
        #[must_use = "finalize or cancel the scoped KMAC state"]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_mac_kmac::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_mac_kmac::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_mac_kmac::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_mac_kmac::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_mac_kmac::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        pub struct $state<'scope> {
            pub(super) core: Core<'scope, cshake::$backend<'scope>>,
        }
        impl $state<'_> {
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
            /// Produces a full-strength public tag; errors preserve its destination.
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
