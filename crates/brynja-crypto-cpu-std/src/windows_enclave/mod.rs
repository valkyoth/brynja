//! Windows VBS enclave sessions with retained SHA-256 results.
//!
//! This is a separate interface: enclave-private results cannot be exposed as
//! host slices. Caller input storage remains outside the enclave. Only explicit
//! public declassification copies a result into ordinary host memory.
//!
//! An application supplies a reviewed, signed image and a policy embedded in
//! its trusted build. Never construct policy from an untrusted adjacent file.
//! Production opening requires Windows signature verification and successful
//! enclave initialization; there is no development-mode runtime fallback.
//! The current protocol admits scalar SHA-256 inputs of at most 1024 bytes.
//! The separate [`sha2`] module uses a version-six worker for full scalar SHA-2
//! streaming. With `strict-sha2-acceleration`, its distinct `open_sha_ni`
//! constructor requires a matching SHA-224/256 image; scalar opening stays scalar.
//! Other hardware routes and Windows ARM64 are not implied by these APIs.
//! Development execution is tested separately; production-signed deployment
//! and independent qualification remain pending. Not certification.

mod engine;
#[cfg(any(
    test,
    all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    )
))]
mod image;
#[cfg(feature = "strict-kmac")]
pub mod kmac;
#[cfg(all(
    feature = "strict-kmac",
    any(
        test,
        all(
            target_os = "windows",
            target_arch = "x86_64",
            target_env = "msvc",
            not(miri),
            not(kani)
        )
    )
))]
mod kmac_avx2_wire;
#[cfg(feature = "strict-kmac")]
mod kmac_wire;
#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
mod native;
#[cfg(all(
    feature = "strict-sha3",
    any(
        test,
        all(
            target_os = "windows",
            target_arch = "x86_64",
            target_env = "msvc",
            not(miri),
            not(kani)
        )
    )
))]
mod parallel_avx2_wire;
#[cfg(all(
    feature = "strict-sha3",
    any(
        test,
        all(
            target_os = "windows",
            target_arch = "x86_64",
            target_env = "msvc",
            not(miri),
            not(kani)
        )
    )
))]
mod parallel_receipt;
#[cfg(feature = "strict-sha3")]
mod parallel_wire;
#[cfg(feature = "strict-sha3")]
pub mod parallelhash;
mod policy;
#[cfg(any(
    test,
    all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    )
))]
mod protocol;
pub mod sha2;
pub mod sha2_batch;
#[cfg(any(
    test,
    all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    )
))]
mod sha2_batch_receipt;
#[cfg(any(
    test,
    all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    )
))]
mod sha2_batch_sha_ni_wire;
mod sha2_batch_wire;
#[cfg(any(
    test,
    all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    )
))]
mod sha2_wire;
#[cfg(feature = "strict-sha3")]
pub mod sha3;
#[cfg(all(
    feature = "strict-sha3",
    any(
        test,
        all(
            target_os = "windows",
            target_arch = "x86_64",
            target_env = "msvc",
            not(miri),
            not(kani)
        )
    )
))]
mod sha3_avx2_wire;
#[cfg(feature = "strict-sha3")]
pub mod sha3_batch;
#[cfg(all(
    feature = "strict-sha3",
    any(
        test,
        all(
            target_os = "windows",
            target_arch = "x86_64",
            target_env = "msvc",
            not(miri),
            not(kani)
        )
    )
))]
mod sha3_batch_avx2_wire;
#[cfg(all(
    feature = "strict-sha3",
    any(
        test,
        all(
            target_os = "windows",
            target_arch = "x86_64",
            target_env = "msvc",
            not(miri),
            not(kani)
        )
    )
))]
mod sha3_batch_receipt;
#[cfg(feature = "strict-sha3")]
mod sha3_batch_wire;
#[cfg(feature = "strict-sha3")]
mod sha3_wire;
#[cfg(feature = "strict-sha2-acceleration")]
pub mod sha512_simd;
#[cfg(all(
    feature = "strict-tuplehash",
    any(
        test,
        all(
            target_os = "windows",
            target_arch = "x86_64",
            target_env = "msvc",
            not(miri),
            not(kani)
        )
    )
))]
mod tuple_avx2_wire;
#[cfg(all(
    feature = "strict-tuplehash",
    any(
        test,
        all(
            target_os = "windows",
            target_arch = "x86_64",
            target_env = "msvc",
            not(miri),
            not(kani)
        )
    )
))]
mod tuple_receipt;
#[cfg(feature = "strict-tuplehash")]
mod tuple_wire;
#[cfg(feature = "strict-tuplehash")]
pub mod tuplehash;
mod unsupported;
pub use brynja_hash_sha2::PublicDeclassification;
#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
use native::Backend;
pub use policy::ImagePolicy;
use std::path::Path;
#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
use unsupported::Backend;

/// Public lifecycle only, never private message length or digest bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// Ready for one bounded request.
    Ready,
    /// A retained digest exists, including a forgotten handle.
    Busy,
    /// No new operations may be started.
    Quarantined,
    /// Clearing and OS destruction were confirmed.
    Closed,
}

/// Fail-closed resource or protocol outcome. No secret data is included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Native Windows x64 VBS support is required.
    Unsupported,
    /// Invalid bounded location, artifact, policy or request size.
    Bounds,
    /// File identity, sharing or import admission failed.
    Image,
    /// Windows trust verification failed; do not retry in a weaker profile.
    Signature,
    /// Platform creation, loading, initialization or residency failed.
    Platform,
    /// A digest still belongs to this session.
    Busy,
    /// An operation failed or its result was abandoned.
    Quarantined,
    /// The session was already closed.
    Closed,
    /// A nonrecycled sequence exhausted its domain.
    Exhausted,
    /// The trusted worker protocol or cleanup receipt was inconsistent.
    Protocol,
    /// Cleanup was not confirmed; resources are retained, not released unsafely.
    Release,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Windows enclave operation rejected: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Thread-bound enclave owner. No Send/Sync/Copy/Clone/Debug or raw handles.
///
/// ```compile_fail,E0277
/// use brynja_crypto_cpu_std::windows_enclave::Session;
/// fn bound<T: Send>() {}
/// bound::<Session>();
/// ```
/// ```compile_fail,E0277
/// use brynja_crypto_cpu_std::windows_enclave::Session;
/// fn bound<T: Sync>() {}
/// bound::<Session>();
/// ```
/// ```compile_fail,E0277
/// use brynja_crypto_cpu_std::windows_enclave::Session;
/// fn bound<T: Copy>() {}
/// bound::<Session>();
/// ```
/// ```compile_fail,E0277
/// use brynja_crypto_cpu_std::windows_enclave::Session;
/// fn bound<T: Clone>() {}
/// bound::<Session>();
/// ```
/// ```compile_fail,E0277
/// use brynja_crypto_cpu_std::windows_enclave::Session;
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<Session>();
/// ```
///
/// Drop attempts clearing and destruction. If these cannot be confirmed, the
/// native mapping and its file guards remain retained, not silently freed.
/// Fatal abort/process termination is not a cleanup guarantee. Use `close` to
/// observe cleanup failure. Forgetting this owner intentionally leaks resources.
#[must_use]
pub struct Session {
    inner: engine::Engine<Backend>,
}
impl Session {
    /// Opens an application-reviewed image using a trusted, static build policy.
    /// Signature/revocation or platform failure returns an error, never fallback.
    /// Deployment must preserve the reviewed host/image and Windows trust chain.
    pub fn open(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        let backend = Backend::open(location, policy)?;
        Ok(Self {
            inner: engine::Engine::new(backend),
        })
    }
    /// Returns the public lifecycle state, not private counters.
    pub fn state(&self) -> State {
        self.inner.state()
    }
    /// Copies up to 1024 caller-owned bytes synchronously into the enclave and
    /// retains the result there. The input borrow ends when this call returns.
    ///
    /// ```compile_fail,E0499
    /// use brynja_crypto_cpu_std::windows_enclave::{Session, Error};
    /// fn reject(owner: &mut Session) -> Result<(), Error> {
    ///     let digest = owner.hash(b"public example")?;
    ///     owner.close()?;
    ///     digest.cancel()
    /// }
    /// ```
    /// ```compile_fail
    /// use brynja_crypto_cpu_std::windows_enclave::{Session, Digest, Error};
    /// fn reject(mut owner: Session) -> Result<Digest<'static>, Error> {
    ///     owner.hash(b"public example")
    /// }
    /// ```
    pub fn hash(&mut self, input: &[u8]) -> Result<Digest<'_>, Error> {
        self.inner.begin(input)?;
        Ok(Digest {
            session: self,
            armed: true,
        })
    }
    /// Confirms cleanup/destruction, also after an abandoned or forgotten digest.
    /// A failure remains Quarantined; it never reports successful closure.
    pub fn close(&mut self) -> Result<(), Error> {
        self.inner.close()
    }
}

/// Exclusive retained result. No byte exposure, token export or cloning.
///
/// ```compile_fail,E0277
/// use brynja_crypto_cpu_std::windows_enclave::Digest;
/// fn bound<T: Send>() {}
/// bound::<Digest<'static>>();
/// ```
/// ```compile_fail,E0277
/// use brynja_crypto_cpu_std::windows_enclave::Digest;
/// fn bound<T: Sync>() {}
/// bound::<Digest<'static>>();
/// ```
/// ```compile_fail,E0277
/// use brynja_crypto_cpu_std::windows_enclave::Digest;
/// fn bound<T: Copy>() {}
/// bound::<Digest<'static>>();
/// ```
/// ```compile_fail,E0277
/// use brynja_crypto_cpu_std::windows_enclave::Digest;
/// fn bound<T: Clone>() {}
/// bound::<Digest<'static>>();
/// ```
/// ```compile_fail,E0277
/// use brynja_crypto_cpu_std::windows_enclave::Digest;
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<Digest<'static>>();
/// ```
/// Drop quarantines; forgetting leaves the parent Busy. The parent still owns
/// cleanup in both cases. Only successful cancel/declassification permits reuse.
#[must_use]
pub struct Digest<'session> {
    session: &'session mut Session,
    armed: bool,
}
impl Digest<'_> {
    /// Replaces the result with SHA-256(result) entirely inside the enclave.
    pub fn rehash(mut self) -> Result<Self, Error> {
        self.armed = false;
        self.session.inner.rehash()?;
        self.armed = true;
        Ok(self)
    }
    /// Releases bytes only after an explicit public-data decision and validated
    /// worker clearing. On failure, the supplied destination remains unchanged.
    pub fn declassify(
        mut self,
        destination: &mut [u8; 32],
        _decision: PublicDeclassification,
    ) -> Result<(), Error> {
        self.armed = false;
        self.session.inner.export(destination)
    }
    /// Clears the retained result without releasing its bytes to the host.
    pub fn cancel(mut self) -> Result<(), Error> {
        self.armed = false;
        self.session.inner.cancel()
    }
}
impl Drop for Digest<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.session.inner.abandon();
        }
    }
}

#[cfg(test)]
mod tests;
