use super::Error;
pub(super) trait Channel {
    fn request(
        &mut self,
        request: super::Request,
        input: &[u8],
        output: Option<&mut [u8]>,
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
pub(super) use super::super::native::parallelhash::Transport;
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
        request: super::Request,
        input: &[u8],
        output: Option<&mut [u8]>,
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
#[cfg(not(test))]
pub(super) enum Transport {}
#[cfg(all(
    test,
    not(all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    ))
))]
pub(super) struct Transport(pub(super) super::tests::Mock);
#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
impl Transport {
    pub(super) fn open(_: &std::path::Path, _: &'static super::ImagePolicy) -> Result<Self, Error> {
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
#[cfg(not(test))]
impl Channel for Transport {
    fn request(&mut self, _: super::Request, _: &[u8], _: Option<&mut [u8]>) -> Result<(), Error> {
        match *self {}
    }
    fn close(&mut self) -> Result<(), Error> {
        match *self {}
    }
}
#[cfg(all(
    test,
    not(all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    ))
))]
impl Channel for Transport {
    fn request(
        &mut self,
        request: super::Request,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<(), Error> {
        self.0.request(request, input, output)
    }
    fn close(&mut self) -> Result<(), Error> {
        self.0.close()
    }
}
