use super::{Error, Limits, resource::Mapping};
use brynja_hash_sha2::{BitString, hardened_in_place::Sha256Workspace};
#[cfg(test)]
mod tests;

/// Reusable scalar SHA-256 on a resident worker stack. Not dump-excluded.
///
/// Captures contain only borrowed addresses and public metadata. No populated
/// state or digest is returned by value from the worker. Forgetting a digest
/// loan cannot suppress session-owned clearing. Qualification remains pending.
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_crypto_cpu_std::macos_resident::Sha256Session>();
/// ```
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_crypto_cpu_std::macos_resident::Sha256Session>();
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {}
/// clone::<brynja_crypto_cpu_std::macos_resident::Sha256Session>();
/// ```
/// ```compile_fail
/// fn debug<T: core::fmt::Debug>() {}
/// debug::<brynja_crypto_cpu_std::macos_resident::Sha256Session>();
/// ```
/// ```compile_fail
/// fn copy<T: Copy>() {}
/// copy::<brynja_crypto_cpu_std::macos_resident::Sha256Session>();
/// ```
pub struct Sha256Session {
    stack: Mapping,
    output: Mapping,
    limits: Limits,
    #[cfg(test)]
    fault: u8,
}
impl Sha256Session {
    /// Preacquires both resources; unsupported targets and OS failures reject.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        if limits.stack_bytes < 65536 || limits.max_chunks == 0 {
            return Err(Error::InvalidSize);
        }
        let stack = Mapping::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let output = Mapping::new(32, limits.max_output_mapping_bytes)?;
        Ok(Self {
            stack,
            output,
            limits,
            #[cfg(test)]
            fault: 0,
        })
    }
    /// Hashes borrowed caller-owned bytes; input storage is not made resident.
    pub fn hash(&mut self, input: &[u8]) -> Result<Digest<'_>, Error> {
        self.hash_chunks(&[input])
    }
    /// Hashes bounded byte-aligned chunks on a fresh joined worker.
    /// Errors clear output. A completed join clears the entire worker payload.
    pub fn hash_chunks(&mut self, chunks: &[&[u8]]) -> Result<Digest<'_>, Error> {
        self.output.clear();
        validate(self.limits, chunks)?;
        let mut guard = OutputGuard {
            output: &mut self.output,
            complete: false,
        };
        let destination = guard.output.bytes_mut();
        let mut result = Err(Error::Invariant);
        #[cfg(test)]
        let fault = self.fault;
        self.stack.run(|| {
            result = compute(chunks, destination);
            #[cfg(test)]
            {
                assert!(fault != 2, "synthetic post-write unwind");
                if fault == 1 {
                    result = Err(Error::Invariant);
                }
            }
        })?;
        result?;
        guard.complete = true;
        drop(guard);
        Ok(Digest {
            output: &mut self.output,
        })
    }
}
fn validate(limits: Limits, chunks: &[&[u8]]) -> Result<(), Error> {
    if chunks.len() > limits.max_chunks {
        return Err(Error::WorkLimit);
    }
    let mut count = 0u64;
    for chunk in chunks {
        count = count
            .checked_add(u64::try_from(chunk.len()).map_err(|_| Error::WorkLimit)?)
            .ok_or(Error::WorkLimit)?;
    }
    if count > limits.max_message_bytes || count > u64::MAX / 8 {
        return Err(Error::WorkLimit);
    }
    Ok(())
}
fn compute(chunks: &[&[u8]], destination: &mut [u8]) -> Result<(), Error> {
    let mut workspace = Sha256Workspace::new();
    let mut staged = [0u8; 32];
    workspace.with(|mut state| {
        for chunk in chunks {
            state.update(chunk).map_err(|_| Error::Invariant)?;
        }
        let tail = BitString::new(&[], 0).map_err(|_| Error::Invariant)?;
        let secret = state
            .finalize_bits_secret(tail, &mut staged)
            .map_err(|_| Error::Invariant)?;
        brynja_core::copy_secret_region(destination, secret.expose()).map_err(|_| Error::Invariant)
    })
}
struct OutputGuard<'a> {
    output: &'a mut Mapping,
    complete: bool,
}
impl Drop for OutputGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.output.clear();
        }
    }
}

/// Explicit borrowed digest; not a public digest or a dump-excluded allocation.
/// Drop clears output. A live loan prevents session reuse.
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_crypto_cpu_std::macos_resident::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_crypto_cpu_std::macos_resident::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn copy<T: Copy>() {}
/// copy::<brynja_crypto_cpu_std::macos_resident::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {}
/// clone::<brynja_crypto_cpu_std::macos_resident::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn debug<T: core::fmt::Debug>() {}
/// debug::<brynja_crypto_cpu_std::macos_resident::Digest<'static>>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::macos_resident::{Sha256Session, Error, Digest};
/// fn escape(s: &mut Sha256Session) -> Result<Digest<'static>, Error> { s.hash(b"abc") }
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::macos_resident::{Sha256Session, Error};
/// fn reuse(s: &mut Sha256Session) -> Result<(), Error> {
///     let first = s.hash(b"abc")?;
///     let _second = s.hash(b"def")?;
///     let _ = first.expose();
///     Ok(())
/// }
/// ```
pub struct Digest<'a> {
    output: &'a mut Mapping,
}
impl Digest<'_> {
    /// Explicit exposure; any caller-created copy is outside this profile.
    pub fn expose(&self) -> &[u8] {
        self.output.bytes()
    }
}
impl Drop for Digest<'_> {
    fn drop(&mut self) {
        self.output.clear();
    }
}
