#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
pub(super) enum Backend {}
#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
impl Backend {
    pub(super) fn open(
        _: &std::path::Path,
        _: &'static super::ImagePolicy,
    ) -> Result<Self, super::Error> {
        Err(super::Error::Unsupported)
    }
}
#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
impl super::engine::Driver for Backend {
    fn begin(&mut self, _: &[u8], _: u64) -> Result<(), super::Error> {
        match *self {}
    }
    fn rehash(&mut self) -> Result<(), super::Error> {
        match *self {}
    }
    fn export(&mut self, _: &mut [u8; 32]) -> Result<(), super::Error> {
        match *self {}
    }
    fn cancel(&mut self) -> Result<(), super::Error> {
        match *self {}
    }
    fn close(&mut self) -> Result<(), super::Error> {
        match *self {}
    }
}
