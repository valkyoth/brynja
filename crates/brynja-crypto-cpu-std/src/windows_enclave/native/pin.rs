use super::{
    super::{Error, ImagePolicy, image},
    sys,
};
use std::path::{Path, PathBuf};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::Read,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, IntoRawHandle},
    },
};

pub(super) struct Pin {
    files: Vec<File>,
    pub(super) location: Vec<u16>,
}
impl Pin {
    pub(super) fn open(location: &Path, policy: &ImagePolicy) -> Result<Self, Error> {
        Self::open_threads(location, policy, 1)
    }
    pub(super) fn open_threads(
        location: &Path,
        policy: &ImagePolicy,
        threads: u32,
    ) -> Result<Self, Error> {
        if !matches!(threads, 1 | 5) {
            return Err(Error::Image);
        }
        let mut wide = Vec::new();
        wide.try_reserve_exact(1024).map_err(|_| Error::Platform)?;
        wide.extend(location.as_os_str().encode_wide().take(1024));
        if !normal_path(&wide) {
            return Err(Error::Bounds);
        }
        let mut files = Vec::new();
        files.try_reserve_exact(32).map_err(|_| Error::Platform)?;
        let mut pin = Self {
            files,
            location: wide,
        };
        pin.directory(3)?;
        let length = pin.location.len();
        for i in 3..length {
            if pin.location.get(i) == Some(&92) {
                pin.directory(i)?;
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x08200000)
            .open(location)
            .map_err(|_| Error::Image)?;
        pin.files.push(file);
        let file = pin.files.last_mut().ok_or(Error::Image)?;
        let metadata = file.metadata().map_err(|_| Error::Image)?;
        if !sys::disk(file.as_raw_handle())
            || metadata.file_attributes() & 0x410 != 0
            || !(512..=16777216).contains(&metadata.len())
        {
            return Err(Error::Image);
        }
        let size = usize::try_from(metadata.len()).map_err(|_| Error::Image)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| Error::Platform)?;
        bytes.resize(size, 0);
        file.read_exact(&mut bytes).map_err(|_| Error::Image)?;
        if file.read(&mut [0; 1]).map_err(|_| Error::Image)? != 0 {
            return Err(Error::Image);
        }
        if threads == 1 {
            image::admit(&bytes, policy)?;
        } else {
            image::admit_threads(&bytes, policy, threads)?;
        }
        // The loader accepts a name, not our handle. Bind that name to the
        // admitted file on its volume, independently of the caller's DOS alias.
        // Keep the original guards alive until the canonical guards are held.
        let handle = file.as_raw_handle();
        let identity = sys::file_identity(handle)?;
        let location = sys::volume_path(handle)?;
        if !volume_path(&location) {
            return Err(Error::Image);
        }
        let mut files = Vec::new();
        files.try_reserve_exact(32).map_err(|_| Error::Platform)?;
        let mut canonical = Self { files, location };
        canonical.directory(49)?;
        for i in 49..canonical.location.len() {
            if canonical.location.get(i) == Some(&92) {
                canonical.directory(i)?;
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x08200000)
            .open(PathBuf::from(OsString::from_wide(&canonical.location)))
            .map_err(|_| Error::Image)?;
        canonical.files.push(file);
        let file = canonical.files.last().ok_or(Error::Image)?;
        if sys::file_identity(file.as_raw_handle())? != identity
            || file.metadata().map_err(|_| Error::Image)?.file_attributes() & 0x410 != 0
            || sys::volume_path(file.as_raw_handle())? != canonical.location
        {
            return Err(Error::Image);
        }
        canonical.location.push(0);
        Ok(canonical)
    }
    fn directory(&mut self, end: usize) -> Result<(), Error> {
        if self.files.len() >= 31 {
            return Err(Error::Bounds);
        }
        let location = PathBuf::from(OsString::from_wide(
            self.location.get(..end).ok_or(Error::Bounds)?,
        ));
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x02200000)
            .open(location)
            .map_err(|_| Error::Image)?;
        self.files.push(file);
        let file = self.files.last().ok_or(Error::Image)?;
        if !sys::disk(file.as_raw_handle())
            || file.metadata().map_err(|_| Error::Image)?.file_attributes() & 0x410 != 0x10
        {
            return Err(Error::Image);
        }
        Ok(())
    }
    pub(super) fn signature(&self) -> Result<(), Error> {
        sys::signature(
            &self.location,
            self.files.last().ok_or(Error::Image)?.as_raw_handle(),
        )
    }
}
impl Drop for Pin {
    fn drop(&mut self) {
        // Reverse order: file before ancestors. Close failures cannot masquerade
        // as confirmed release of the admission guard.
        while let Some(file) = self.files.pop() {
            sys::close(file.into_raw_handle());
        }
    }
}
fn normal_path(location: &[u16]) -> bool {
    if !(4..1024).contains(&location.len())
        || !location.first().is_some_and(|c| (65..=90).contains(c))
        || location.get(1..3) != Some(&[58, 92])
    {
        return false;
    }
    components(location.get(3..).unwrap_or_default())
}
fn volume_path(location: &[u16]) -> bool {
    if !(50..1024).contains(&location.len())
        || !location
            .iter()
            .take(11)
            .copied()
            .eq(r"\\?\Volume{".encode_utf16())
        || location.get(47..49) != Some(&[125, 92])
    {
        return false;
    }
    for (i, c) in location.iter().skip(11).take(36).copied().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if c != 45 {
                return false;
            }
        } else if !matches!(c, 48..=57 | 65..=70 | 97..=102) {
            return false;
        }
    }
    components(location.get(49..).unwrap_or_default())
}
fn components(location: &[u16]) -> bool {
    let mut component = 0usize;
    let mut previous = 0;
    for &c in location.iter().chain(core::iter::once(&92)) {
        if c == 92 {
            if component == 0 || matches!(previous, 32 | 46) {
                return false;
            }
            component = 0;
        } else {
            if c < 32 || matches!(c, 58 | 47 | 34 | 60 | 62 | 124 | 63 | 42) {
                return false;
            }
            component = component.saturating_add(1);
        }
        previous = c;
    }
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_bounded_volume_guid_paths_reach_the_loader() {
        let prefix = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\";
        for suffix in ["worker.dll", r"reviewed\worker.dll"] {
            assert!(super::volume_path(
                &format!("{prefix}{suffix}")
                    .encode_utf16()
                    .collect::<Vec<_>>()
            ));
        }
        for suffix in [
            "",
            r"..\worker.dll",
            r".\worker.dll",
            "a.dll:stream",
            "a.dll.",
            "a.dll ",
            "a\0.dll",
            r"a\\b.dll",
        ] {
            assert!(!super::volume_path(
                &format!("{prefix}{suffix}")
                    .encode_utf16()
                    .collect::<Vec<_>>()
            ));
        }
        for bad in [
            r"\\?\C:\worker.dll",
            r"C:\worker.dll",
            r"\\server\worker.dll",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdeg}\worker.dll",
            r"\\?\Volume{01234567_89ab-cdef-0123-456789abcdef}\worker.dll",
        ] {
            assert!(!super::volume_path(&bad.encode_utf16().collect::<Vec<_>>()));
        }
        assert!(!super::volume_path(
            &format!("{prefix}{}", "a".repeat(1024))
                .encode_utf16()
                .collect::<Vec<_>>()
        ));
    }
    #[test]
    fn reject_ambiguous_or_unbounded_locations() {
        for good in ["C:\\worker.dll", "C:\\reviewed\\worker.dll"] {
            assert!(super::normal_path(&good.encode_utf16().collect::<Vec<_>>()));
        }
        for bad in [
            "worker.dll",
            "c:\\worker.dll",
            "C:/worker.dll",
            "C:\\",
            "C:\\\\worker.dll",
            "C:\\..\\worker.dll",
            "C:\\.\\worker.dll",
            "C:\\worker.dll ",
            "C:\\worker.dll.",
            "C:\\worker.dll:stream",
            "C:\\worker\0.dll",
            "\\\\server\\worker.dll",
            "\\\\?\\C:\\worker.dll",
        ] {
            assert!(!super::normal_path(&bad.encode_utf16().collect::<Vec<_>>()));
        }
        assert!(!super::normal_path(&vec![65; 1024]));
    }
}
