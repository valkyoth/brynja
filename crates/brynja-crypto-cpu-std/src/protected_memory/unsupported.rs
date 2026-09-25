//! No emulated protection or ordinary-heap fallback on unsupported platforms.
use super::Error;

pub(super) enum Mapping {}

impl Mapping {
    pub(super) fn stack(_: usize, _: usize) -> Result<Self, Error> {
        Err(Error::Unsupported)
    }
    pub(super) fn run<F: FnOnce() + Send>(&mut self, _: F) -> Result<(), Error> {
        match *self {}
    }
    pub(super) fn new(_: usize, _: usize) -> Result<Self, Error> {
        Err(Error::Unsupported)
    }
    pub(super) fn bytes(&self) -> &[u8] {
        match *self {}
    }
    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        match *self {}
    }
    pub(super) fn clear(&mut self) {
        match *self {}
    }
    pub(super) fn close(&mut self) -> Result<(), Error> {
        match *self {}
    }
}
