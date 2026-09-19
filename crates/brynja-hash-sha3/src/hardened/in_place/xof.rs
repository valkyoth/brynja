use super::{
    Cleanup, HardenedFips202Owner, HardenedSha3Error, HardenedSha3SecretOutput, PhantomData,
    Sha3PublicDeclassification, begin_secret, finish_secret,
};
use crate::hardened::sponge::{SHAKE_SUFFIX, SHAKE_SUFFIX_BITS};
use crate::{Fips202BitString, Fips202Output, sp800185::absorb_cshake_prefix};

// Only this exclusive reference and lifecycle flag move into the reader.
// The enclosing workspace scope independently guards the actual storage.
struct Borrowed<'scope, const RATE: usize> {
    owner: &'scope mut HardenedFips202Owner<RATE>,
    active: bool,
    thread_bound: PhantomData<*mut ()>,
}

impl<const RATE: usize> Borrowed<'_, RATE> {
    fn run<R>(
        &mut self,
        operation: impl FnOnce(&mut HardenedFips202Owner<RATE>) -> Result<R, HardenedSha3Error>,
    ) -> Result<R, HardenedSha3Error> {
        if !self.active {
            return Err(HardenedSha3Error::StateConsumed);
        }
        self.active = false;
        let mut cleanup = Cleanup {
            owner: &mut *self.owner,
            keep: false,
        };
        let result = operation(cleanup.owner);
        if result.is_ok() {
            cleanup.keep = true;
            self.active = true;
        }
        result
    }

    fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha3Error> {
        self.run(|owner| {
            owner
                .update(input)
                .map_err(|()| HardenedSha3Error::MessageTooLong)
        })
    }

    fn finalize(&mut self, input: Option<Fips202BitString<'_>>) -> Result<(), HardenedSha3Error> {
        self.run(|owner| {
            let partial = if let Some(input) = input {
                let bits = u128::try_from(input.bit_len())
                    .map_err(|_| HardenedSha3Error::MessageTooLong)?;
                owner
                    .check_message_bits(bits)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)?;
                let (complete, partial) = crate::hardened::sponge::split_input(input);
                owner
                    .update(complete)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)?;
                partial
            } else {
                None
            };
            if owner.cshake_is_customized() {
                owner.finalize(partial, 0x04, 3);
            } else {
                owner.finalize(partial, SHAKE_SUFFIX, SHAKE_SUFFIX_BITS);
            }
            owner.wipe_cshake_metadata();
            Ok(())
        })
    }

    fn secret<'out>(
        &mut self,
        destination: &'out mut [u8],
        valid: Option<u8>,
    ) -> Result<HardenedSha3SecretOutput<'out>, HardenedSha3Error> {
        let length = destination.len();
        // Establish clearing before checking terminal state, including empty output.
        // Initialization failure must also terminate and clear this reader.
        let mut initialization = match begin_secret(destination) {
            Ok(initialization) => initialization,
            Err(error) => {
                self.active = false;
                self.owner.wipe();
                return Err(error);
            }
        };
        self.run(|owner| {
            if let Some(initialization) = initialization.as_mut() {
                if let Some(valid) = valid {
                    owner.squeeze_final_bits_secret(length, valid, initialization)?;
                } else {
                    owner.squeeze_secret(initialization, length)?;
                }
            } else {
                owner
                    .check_output_bytes(0)
                    .map_err(|()| HardenedSha3Error::OutputTooLong)?;
            }
            finish_secret(initialization)
        })
    }
}

impl<const RATE: usize> Drop for Borrowed<'_, RATE> {
    fn drop(&mut self) {
        self.owner.wipe();
    }
}

macro_rules! xof {
    ($workspace:ident, $state:ident, $reader:ident, $rate:literal) => {
        /// Opaque caller-owned storage for a scoped hardened XOF computation.
        ///
        /// Secret storage stays borrowed through absorption and reading. Scope
        /// exit clears all owned regions, even if a handle was forgotten or the
        /// callback recoverably unwinds. This does not erase compiler copies,
        /// registers, caller inputs or abort-time remnants.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ">();\n```")]
        pub struct $workspace {
            owner: HardenedFips202Owner<$rate>,
            thread_bound: PhantomData<*mut ()>,
        }
        impl $workspace {
            /// Creates secret-free, allocation-free storage.
            #[must_use]
            pub fn new() -> Self {
                Self { owner: HardenedFips202Owner::new(), thread_bound: PhantomData }
            }

            fn scope<R>(&mut self, operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> R {
                self.owner.wipe();
                let cleanup = Cleanup { owner: &mut self.owner, keep: false };
                operation($state { inner: Borrowed { owner: &mut *cleanup.owner, active: true, thread_bound: PhantomData } })
            }
        }
        impl Default for $workspace {
            fn default() -> Self { Self::new() }
        }

        /// Exclusive absorbing handle; no secret owner moves on finalization.
        ///
        /// An update error clears the owner and terminates the handle. There is
        /// no public accumulated-length or preflight-length query.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[must_use = "finalize or cancel the scoped state"]
        pub struct $state<'scope> { inner: Borrowed<'scope, $rate> }
        impl<'scope> $state<'scope> {
            /// Absorbs input; failure or recoverable unwind clears and terminates.
            pub fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha3Error> { self.inner.update(input) }

            /// Consumes the absorbing handle; transfers only its exclusive borrow.
            pub fn finalize_xof(mut self) -> Result<$reader<'scope>, HardenedSha3Error> {
                self.inner.finalize(None)?;
                Ok($reader { inner: self.inner })
            }

            /// Includes one final canonical bit string before starting output.
            pub fn finalize_bits_xof(mut self, input: Fips202BitString<'_>) -> Result<$reader<'scope>, HardenedSha3Error> {
                self.inner.finalize(Some(input))?;
                Ok($reader { inner: self.inner })
            }

            /// Clears the borrowed state without output.
            pub fn cancel(self) {}
        }

        /// Scoped incremental output reader, borrowing the original workspace.
        ///
        /// Errors clear and terminate the reader. Secret destinations are cleared
        /// on failure; public destinations are preserved. Dropping or cancelling
        /// clears the state, while scope exit also covers forgotten readers.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[must_use = "read or cancel the scoped reader"]
        pub struct $reader<'scope> { inner: Borrowed<'scope, $rate> }
        impl $reader<'_> {
            /// Emits an explicitly declassified byte fragment.
            pub fn squeeze_public(&mut self, destination: &mut [u8], authority: Sha3PublicDeclassification) -> Result<(), HardenedSha3Error> {
                self.inner.run(|owner| owner.squeeze_public(destination, authority))
            }

            /// Transfers typed secret ownership of a byte fragment.
            pub fn squeeze_secret<'out>(&mut self, destination: &'out mut [u8]) -> Result<HardenedSha3SecretOutput<'out>, HardenedSha3Error> {
                self.inner.secret(destination, None)
            }

            /// Emits final canonical bits and consumes/clears the reader.
            pub fn squeeze_final_bits_public(mut self, output: Fips202Output<'_>, authority: Sha3PublicDeclassification) -> Result<(), HardenedSha3Error> {
                self.inner.run(|owner| owner.squeeze_final_bits_public(output, authority))
            }

            /// Transfers final canonical secret bits and consumes/clears the reader.
            pub fn squeeze_final_bits_secret<'out>(mut self, output: Fips202Output<'out>) -> Result<HardenedSha3SecretOutput<'out>, HardenedSha3Error> {
                let (destination, valid) = output.into_parts();
                self.inner.secret(destination, Some(valid))
            }

            /// Clears the borrowed state without further output.
            pub fn cancel(self) {}
        }
    };
}

xof!(Shake128Workspace, Shake128, Shake128Reader, 168);
xof!(Shake256Workspace, Shake256, Shake256Reader, 136);
xof!(Cshake128Workspace, Cshake128, Cshake128Reader, 168);
xof!(Cshake256Workspace, Cshake256, Cshake256Reader, 136);

macro_rules! shake_scope {
    ($workspace:ident, $state:ident) => {
        impl $workspace {
            /// Runs one scoped SHAKE computation; neither state nor reader can escape.
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nlet escaped = w.with(|state| state);\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nlet escaped = w.with(|state| state.finalize_xof());\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nw.with(|_state| w.with(|_other| ()));\n```")]
            pub fn with<R>(&mut self, operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> R { self.scope(operation) }
        }
    };
}
shake_scope!(Shake128Workspace, Shake128);
shake_scope!(Shake256Workspace, Shake256);

macro_rules! cshake_scope {
    ($workspace:ident, $state:ident, $rate:literal) => {
        impl $workspace {
            /// Initializes byte-oriented N/S in the borrowed storage, then runs
            /// the callback. Empty N/S is SHAKE. Setup errors clear the workspace
            /// and do not call the callback. Caller-owned N/S is not erased.
            pub fn with<R>(&mut self, function_name: &[u8], customization: &[u8], operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> Result<R, HardenedSha3Error> {
                let n = Fips202BitString::new(function_name, if function_name.is_empty() { 0 } else { 8 }).map_err(|_| HardenedSha3Error::MessageTooLong)?;
                let s = Fips202BitString::new(customization, if customization.is_empty() { 0 } else { 8 }).map_err(|_| HardenedSha3Error::MessageTooLong)?;
                self.with_bits(n, s, operation)
            }

            /// Initializes canonical arbitrary-bit N/S in borrowed storage.
            /// The outer Result covers setup; the inner value is the callback result.
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nlet escaped = w.with(b\"\", b\"\", |state| state);\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nlet escaped = w.with(b\"\", b\"\", |state| state.finalize_xof());\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nw.with(b\"\", b\"\", |_state| w.with(b\"\", b\"\", |_other| ()));\n```")]
            pub fn with_bits<R>(&mut self, function_name: Fips202BitString<'_>, customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> Result<R, HardenedSha3Error> {
                self.scope(|mut state| {
                    state.inner.run(|owner| {
                        let customized = absorb_cshake_prefix($rate, function_name, customization, |bytes| owner.update(bytes)).map_err(|()| HardenedSha3Error::MessageTooLong)?;
                        owner.remember_cshake_setup(customized);
                        Ok(())
                    })?;
                    Ok(operation(state))
                })
            }
        }
    };
}
cshake_scope!(Cshake128Workspace, Cshake128, 168);
cshake_scope!(Cshake256Workspace, Cshake256, 136);

#[cfg(test)]
mod tests;
