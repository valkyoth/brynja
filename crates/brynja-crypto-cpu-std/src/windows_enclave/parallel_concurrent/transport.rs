use super::{Channel, Error, Request};

#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
pub(super) use super::super::native::parallel_concurrent::Transport;
#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
impl Channel for Transport {
    fn execute(&mut self, request: &Request<'_>, output: &mut [u8; 1024]) -> Result<(), Error> {
        Self::execute(self, request, output)
    }
    fn settled(&self) -> Result<(), Error> {
        Self::settled(self)
    }
}
#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
pub(super) struct Transport;
#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
impl Transport {
    pub(super) fn open_avx2(
        _: &std::path::Path,
        _: &'static super::ImagePolicy,
    ) -> Result<Self, Error> {
        Err(Error::Unsupported)
    }
}
#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
impl Channel for Transport {
    fn execute(&mut self, request: &Request<'_>, _: &mut [u8; 1024]) -> Result<(), Error> {
        let _ = request.header()?;
        Err(Error::Unsupported)
    }
    fn settled(&self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}
