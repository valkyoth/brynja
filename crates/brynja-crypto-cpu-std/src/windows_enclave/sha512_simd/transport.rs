use super::{Error, Input, Request};
pub(super) trait Channel {
    fn request(
        &mut self,
        request: Request,
        input: &[Input<'_>; 4],
        output: Option<&mut [u8; 256]>,
    ) -> Result<(), Error>;
    fn close(&mut self) -> Result<(), Error>;
}
#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
pub(super) use super::super::native::sha512_simd::Transport;
#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
impl Channel for Transport {
    fn request(
        &mut self,
        request: Request,
        input: &[Input<'_>; 4],
        output: Option<&mut [u8; 256]>,
    ) -> Result<(), Error> {
        Self::request(self, request, input, output)
    }
    fn close(&mut self) -> Result<(), Error> {
        Self::close(self)
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
    fn request(
        &mut self,
        _: Request,
        _: &[Input<'_>; 4],
        _: Option<&mut [u8; 256]>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn close(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}
