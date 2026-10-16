use super::Error;

#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    target_endian = "little",
    target_pointer_width = "64",
    not(any(miri, kani))
))]
mod darwin;
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    target_endian = "little",
    target_pointer_width = "64",
    not(any(miri, kani))
))]
pub(super) use darwin::Mapping;

#[cfg(not(all(
    target_os = "macos",
    target_arch = "aarch64",
    target_endian = "little",
    target_pointer_width = "64",
    not(any(miri, kani))
)))]
pub(super) use unsupported::Mapping;
#[cfg(not(all(
    target_os = "macos",
    target_arch = "aarch64",
    target_endian = "little",
    target_pointer_width = "64",
    not(any(miri, kani))
)))]
mod unsupported {
    use super::Error;
    // Unconstructible externally; preserves affine type properties on all targets.
    pub(in super::super) struct Mapping(core::marker::PhantomData<std::rc::Rc<()>>);
    impl Mapping {
        pub(in super::super) fn new(_: usize, _: usize) -> Result<Self, Error> {
            Err(Error::Unsupported)
        }
        pub(in super::super) fn bytes(&self) -> &[u8] {
            &[]
        }
        pub(in super::super) fn bytes_mut(&mut self) -> &mut [u8] {
            &mut []
        }
        pub(in super::super) fn clear(&mut self) {}
        pub(in super::super) fn run<F: FnOnce() + Send>(&mut self, _: F) -> Result<(), Error> {
            Err(Error::Unsupported)
        }
    }
}

#[cfg(any(
    test,
    all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani)))
))]
#[derive(Clone, Copy)]
struct Layout {
    page: usize,
    payload: usize,
    total: usize,
}
#[cfg(any(
    test,
    all(target_os = "macos", target_arch = "aarch64", not(any(miri, kani)))
))]
impl Layout {
    fn new(bytes: usize, max: usize, page: usize) -> Result<Self, Error> {
        if bytes == 0 || !page.is_power_of_two() {
            return Err(Error::InvalidSize);
        }
        let payload = bytes
            .checked_next_multiple_of(page)
            .ok_or(Error::InvalidSize)?;
        let total = page
            .checked_mul(2)
            .and_then(|guards| payload.checked_add(guards))
            .filter(|total| *total <= isize::MAX as usize)
            .ok_or(Error::InvalidSize)?;
        if total > max {
            return Err(Error::ResourceLimit);
        }
        Ok(Self {
            page,
            payload,
            total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn geometry_is_checked_before_allocation() -> Result<(), Error> {
        for (page, total, under) in [(4096, 12288, 12287), (16384, 49152, 49151)] {
            let layout = Layout::new(32, usize::MAX, page)?;
            assert_eq!(layout.page, page);
            assert_eq!(layout.payload, page);
            assert_eq!(layout.total, total);
            assert!(matches!(
                Layout::new(32, under, page),
                Err(Error::ResourceLimit)
            ));
        }
        for (bytes, page) in [(0, 16384), (usize::MAX, 16384), (1, 0), (1, 3)] {
            assert!(matches!(
                Layout::new(bytes, usize::MAX, page),
                Err(Error::InvalidSize)
            ));
        }
        Ok(())
    }
}
