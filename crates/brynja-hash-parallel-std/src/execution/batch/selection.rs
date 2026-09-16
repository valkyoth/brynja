use super::{Error, Preference, leaf};
use brynja_crypto_cpu_std::keccak_hardened_batch as hosted;
pub(super) enum Selection {
    Hosted(hosted::Authority),
    Static(leaf::Authority),
}
impl Selection {
    pub(super) fn new(preference: Preference) -> Result<Self, Error> {
        if preference == Preference::RequireStatic {
            let kernel = if cfg!(target_arch = "aarch64") {
                leaf::Kernel::Neon
            } else {
                leaf::Kernel::Avx2
            };
            return leaf::Authority::for_compiled_target(kernel)
                .map(Self::Static)
                .map_err(|e| Error::Batch(leaf::Error::Hash(hosted::ExecutionError::Backend(e))));
        }
        let mode = match preference {
            Preference::Portable => hosted::Mode::Portable,
            Preference::Prefer => hosted::Mode::Prefer,
            Preference::Require | Preference::RequireStatic => hosted::Mode::Require,
        };
        hosted::Authority::new(mode)
            .map(Self::Hosted)
            .map_err(Error::Hosted)
    }
    pub(super) fn executor(&self, minimum: usize) -> Result<leaf::Executor<'_>, Error> {
        match self {
            Self::Hosted(owner) => owner.executor(minimum).map_err(Error::Hosted),
            Self::Static(owner) => leaf::Executor::with_session(
                owner.session().map_err(|e| {
                    Error::Batch(leaf::Error::Hash(hosted::ExecutionError::Backend(e)))
                })?,
                leaf::Mode::Require,
                minimum,
            )
            .map_err(|e| Error::Batch(leaf::Error::Hash(e))),
        }
    }
}
