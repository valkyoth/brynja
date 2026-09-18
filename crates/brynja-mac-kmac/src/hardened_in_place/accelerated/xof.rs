use super::super::reader::Output;
use super::{Core, KeccakSession, Report, backend::Backend, cshake, fixed};
use crate::{
    Fips202BitString, KmacError, KmacKeyPolicy, KmacPublicDeclassification, KmacSecretOutput,
    KmacServiceStatus,
};

macro_rules! xof {
    ($workspace:ident, $state:ident, $reader:ident, $fixed:ident, $backend:ident, $backend_reader:ident) => {
        /// Caller-owned accelerated KMACXOF storage. The workspace is borrowed
        /// before key absorption; outer guards also clear forgotten readers.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        pub struct $workspace<'authority> {
            inner: fixed::$fixed<'authority>,
        }
        impl<'authority> $workspace<'authority> {
            /// Binds an existing authority without accepting secret input.
            pub fn new(session: KeccakSession<'authority>) -> Result<Self, KmacError> {
                Ok(Self { inner: fixed::$fixed::new(session)? })
            }
            /// Backend/health metadata only; never message or output length.
            #[must_use]
            pub fn report(&self) -> Report { self.inner.report() }
            /// Runs a production byte-key scope; setup failure skips the callback.
            #[doc = concat!("```compile_fail\nuse brynja_mac_kmac::execution::in_place::", stringify!($workspace), ";\nfn escape(w: &mut ", stringify!($workspace), "<'_>) { let state = w.with(&[0;32], b\"\", |state| state); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_mac_kmac::execution::in_place::", stringify!($workspace), ";\nfn escape(w: &mut ", stringify!($workspace), "<'_>) { let reader = w.with(&[0;32], b\"\", |state| state.finalize_xof()); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_mac_kmac::execution::in_place::", stringify!($workspace), ";\nfn overlap(w: &mut ", stringify!($workspace), "<'_>) { w.with(&[0;32], b\"\", |_| w.with(&[0;32], b\"\", |_| ())); }\n```")]
            pub fn with<R>(
                &mut self,
                key: &[u8],
                customization: &[u8],
                operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R,
            ) -> Result<R, KmacError> {
                self.inner.with(key, customization, |state| {
                    operation($state { core: state.core })
                })
            }
            /// Production canonical-bit scope, requiring a full-strength key.
            pub fn with_bits<R>(
                &mut self,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
                operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R,
            ) -> Result<R, KmacError> {
                self.inner.with_bits(key, customization, |state| {
                    operation($state { core: state.core })
                })
            }
            /// Exact-conformance byte-key scope, including short/empty keys.
            #[cfg(feature = "conformance-testing")]
            pub fn with_conformance<R>(
                &mut self,
                key: &[u8],
                customization: &[u8],
                operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R,
            ) -> Result<R, KmacError> {
                self.inner.with_conformance(key, customization, |state| {
                    operation($state { core: state.core })
                })
            }
            /// Exact-conformance canonical-bit scope; production finalizers
            /// still reject weak keys.
            #[cfg(feature = "conformance-testing")]
            pub fn with_bits_conformance<R>(
                &mut self,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
                operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R,
            ) -> Result<R, KmacError> {
                self.inner
                    .with_bits_conformance(key, customization, |state| {
                        operation($state { core: state.core })
                    })
            }
            /// Production byte-key scope with caller staging for large public reads.
            /// All staging is cleared even on setup rejection or recoverable unwind.
            pub fn with_scratch<R>(&mut self, key: &[u8], customization: &[u8], scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, KmacError> {
                self.inner.with_scratch(key, customization, scratch, |state| operation($state { core: state.core }))
            }
            /// Production canonical-bit scope with caller staging.
            pub fn with_bits_and_scratch<R>(&mut self, key: Fips202BitString<'_>, customization: Fips202BitString<'_>, scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, KmacError> {
                self.inner.with_bits_and_scratch(key, customization, scratch, |state| operation($state { core: state.core }))
            }
            /// Conformance-only canonical-bit scope with caller staging.
            #[cfg(feature = "conformance-testing")]
            pub fn with_bits_and_scratch_conformance<R>(&mut self, key: Fips202BitString<'_>, customization: Fips202BitString<'_>, scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, KmacError> {
                self.inner.with_bits_and_scratch_conformance(key, customization, scratch, |state| operation($state { core: state.core }))
            }
        }
        /// Exclusive absorbing handle. No secret owner moves on finalization.
        /// Errors clear and terminate; there are no accumulated-length queries.
        #[must_use = "finalize or cancel the scoped KMACXOF state"]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        pub struct $state<'scope, 'authority> {
            core: Core<'scope, Backend<cshake::$backend<'scope, 'authority>, &'scope mut [u8]>>,
        }
        impl<'scope, 'authority> $state<'scope, 'authority> {
            /// Returns key-strength classification, not exact key length.
            #[must_use]
            pub fn key_policy(&self) -> KmacKeyPolicy {
                self.core.key_policy()
            }
            /// Always non-approved; no FIPS validation is claimed.
            #[must_use]
            pub const fn service_status(&self) -> KmacServiceStatus {
                KmacServiceStatus::NonApproved
            }
            /// Absorbs bytes; an error clears and terminates the state.
            pub fn update(&mut self, input: &[u8]) -> Result<(), KmacError> {
                self.core.update(input)
            }
            /// Starts production XOF output with right_encode(0).
            pub fn finalize_xof(self) -> Result<$reader<'scope, 'authority>, KmacError> {
                self.finish(None, true)
            }
            /// Includes final canonical message bits and consumes the state.
            pub fn finalize_bits_xof(
                self,
                input: Fips202BitString<'_>,
            ) -> Result<$reader<'scope, 'authority>, KmacError> {
                self.finish(Some(input), true)
            }
            /// Starts exact-conformance XOF output, including weak keys.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_xof_conformance(self) -> Result<$reader<'scope, 'authority>, KmacError> {
                self.finish(None, false)
            }
            /// Exact-conformance final message bits and XOF transition.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_bits_xof_conformance(
                self,
                input: Fips202BitString<'_>,
            ) -> Result<$reader<'scope, 'authority>, KmacError> {
                self.finish(Some(input), false)
            }
            fn finish(
                self,
                input: Option<Fips202BitString<'_>>,
                production: bool,
            ) -> Result<$reader<'scope, 'authority>, KmacError> {
                let (reader, cleanup) = self.core.finish_xof(input, production)?;
                Ok($reader {
                    inner: Output::new(reader, cleanup),
                })
            }
            /// Consumes the handle and clears without producing output.
            pub fn cancel(self) {}
        }
        /// Exclusive incremental reader borrowing the original workspace.
        /// Errors terminate and clear; scope exit also covers forgotten readers.
        /// Public writes are transactional. Secret destinations clear on errors
        /// and when their returned typed output is dropped.
        #[must_use = "read or cancel the scoped KMACXOF reader"]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_mac_kmac::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        pub struct $reader<'scope, 'authority> {
            inner: Output<'scope, Backend<cshake::$backend_reader<'scope, 'authority>, &'scope mut [u8]>>,
        }
        impl $reader<'_, '_> {
            /// Transactional public fragment. The scope's scratch must cover this
            /// entire read (168 bytes by default); insufficient scratch is terminal.
            pub fn squeeze_public(
                &mut self,
                output: &mut [u8],
                _authority: KmacPublicDeclassification,
            ) -> Result<(), KmacError> {
                self.inner.public(output)
            }
            /// Emits a typed secret fragment; its destination borrow is separate
            /// from the computation scope and may outlive that scope.
            pub fn squeeze_secret<'out>(
                &mut self,
                output: &'out mut [u8],
            ) -> Result<KmacSecretOutput<'out>, KmacError> {
                self.inner.secret(output)
            }
            /// Emits final canonical public bits, consuming
            /// and clearing the reader even on shape errors.
            pub fn squeeze_final_bits_public(
                self,
                output: &mut [u8],
                valid: u8,
                _authority: KmacPublicDeclassification,
            ) -> Result<(), KmacError> {
                self.inner.final_public(output, valid)
            }
            /// Emits final canonical secret bits, consuming the reader. Shape
            /// errors also clear the entire supplied destination.
            pub fn squeeze_final_bits_secret<'out>(
                self,
                output: &'out mut [u8],
                valid: u8,
            ) -> Result<KmacSecretOutput<'out>, KmacError> {
                self.inner.final_secret(output, valid)
            }
            /// Always non-approved; no FIPS validation is claimed.
            #[must_use]
            pub const fn service_status(&self) -> KmacServiceStatus {
                KmacServiceStatus::NonApproved
            }
            /// Consumes and clears the reader without further output.
            pub fn cancel(self) {}
        }
    };
}
xof!(
    KmacXof128Workspace,
    KmacXof128,
    KmacXof128Reader,
    Kmac128Workspace,
    Cshake128,
    Cshake128Reader
);
xof!(
    KmacXof256Workspace,
    KmacXof256,
    KmacXof256Reader,
    Kmac256Workspace,
    Cshake256,
    Cshake256Reader
);
