//! Hold an exclusively created temporary NT link until the image pin retires.
//! A shared GLOBALROOT name is not immutable in the per-logon DOS namespace.
#![allow(unsafe_code)]
use super::{Error, sys};
use core::ffi::c_void;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

type Handle = *mut c_void;
#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: Handle,
    name: *const Unicode,
    flags: u32,
    security: *const c_void,
    quality: *const c_void,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateSymbolicLinkObject(
        handle: *mut Handle,
        access: u32,
        attributes: *const Attributes,
        target: *const Unicode,
    ) -> i32;
}
static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) struct ImageName {
    handle: Handle,
    location: Vec<u16>,
}
impl ImageName {
    pub(super) fn create(canonical: &[u16]) -> Result<Self, Error> {
        let prefix = r"\\?\GLOBALROOT";
        if !canonical
            .iter()
            .take(prefix.len())
            .copied()
            .eq(prefix.encode_utf16())
        {
            return Err(Error::Image);
        }
        let target = canonical.get(prefix.len()..).ok_or(Error::Image)?;
        if target.first() != Some(&92) || target.contains(&0) || target.len() >= 1024 {
            return Err(Error::Image);
        }
        let sequence = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::Bounds)?;
        let mut name = String::new();
        name.try_reserve_exact(80).map_err(|_| Error::Platform)?;
        write!(
            &mut name,
            "BrynjaImage-{}-{sequence}.dll",
            std::process::id()
        )
        .map_err(|_| Error::Platform)?;
        let mut native = Vec::new();
        native.try_reserve_exact(84).map_err(|_| Error::Platform)?;
        native.extend(r"\??\".encode_utf16());
        native.extend(name.encode_utf16());
        let mut location = Vec::new();
        location
            .try_reserve_exact(85)
            .map_err(|_| Error::Platform)?;
        location.extend(r"\\?\".encode_utf16());
        location.extend(name.encode_utf16());
        location.push(0);
        let name = unicode(&native)?;
        let target = unicode(target)?;
        let attributes = Attributes {
            length: 48,
            root: core::ptr::null_mut(),
            name: &name,
            // Case-insensitive only: no OPENIF, PERMANENT or inheritable handle.
            flags: 0x40,
            security: core::ptr::null(),
            quality: core::ptr::null(),
        };
        let mut handle = core::ptr::null_mut();
        // SAFETY: fixed x64 NT ABI layouts; all counted UTF-16 buffers and output
        // storage live through the synchronous call. QUERY access only. A name
        // collision rejects rather than opening an attacker-created object.
        let status = unsafe { NtCreateSymbolicLinkObject(&mut handle, 1, &attributes, &target) };
        if status != 0 || handle.is_null() {
            if !handle.is_null() {
                sys::close(handle);
            }
            return Err(Error::Image);
        }
        Ok(Self { handle, location })
    }
    pub(super) fn location(&self) -> &[u16] {
        &self.location
    }
}
impl Drop for ImageName {
    fn drop(&mut self) {
        // Temporary object names stay present while any handle remains open.
        // Keep this guard through file-pin retirement; never reuse its name.
        sys::close(self.handle);
    }
}
fn unicode(value: &[u16]) -> Result<Unicode, Error> {
    let length = value
        .len()
        .checked_mul(2)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or(Error::Bounds)?;
    Ok(Unicode {
        length,
        maximum: length,
        buffer: value.as_ptr(),
    })
}
const _: () = {
    assert!(core::mem::size_of::<Unicode>() == 16);
    assert!(core::mem::size_of::<Attributes>() == 48);
    assert!(core::mem::offset_of!(Attributes, name) == 16);
};
