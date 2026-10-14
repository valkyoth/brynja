//! Hold an exclusively created temporary NT link until the image pin retires.
//! A shared GLOBALROOT name is not immutable in the per-logon DOS namespace.
#![allow(unsafe_code)]
use super::{Error, sys};
use core::ffi::c_void;
use core::fmt::Write;

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
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: Handle, buffer: *mut u8, size: u32, flags: u32) -> i32;
}

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
        for _ in 0..4 {
            let mut nonce = [0u8; 16];
            // SAFETY: the system RNG writes exactly the initialized array's
            // length. Null provider plus BCRYPT_USE_SYSTEM_PREFERRED_RNG is the
            // documented pairing. This is namespace entropy, not key material.
            if unsafe { BCryptGenRandom(core::ptr::null_mut(), nonce.as_mut_ptr(), 16, 2) } != 0 {
                return Err(Error::Platform);
            }
            if let Some(owner) = Self::create_nonce(target, &nonce)? {
                return Ok(owner);
            }
        }
        Err(Error::Image)
    }
    // None means an existing name, never an adopted existing object.
    fn create_nonce(target: &[u16], nonce: &[u8; 16]) -> Result<Option<Self>, Error> {
        let mut name = String::new();
        name.try_reserve_exact(80).map_err(|_| Error::Platform)?;
        name.push_str("BrynjaImage-");
        for byte in nonce {
            write!(&mut name, "{byte:02x}").map_err(|_| Error::Platform)?;
        }
        name.push_str(".dll");
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
            // OBJ_EXCLUSIVE | OBJ_CASE_INSENSITIVE. Other processes cannot
            // retain the object. No OPENIF, PERMANENT or inheritable handle.
            flags: 0x60,
            security: core::ptr::null(),
            quality: core::ptr::null(),
        };
        let mut handle = core::ptr::null_mut();
        // SAFETY: fixed x64 NT ABI layouts; all counted UTF-16 buffers and output
        // storage live through the synchronous call. QUERY access only. A name
        // collision retries rather than opening an attacker-created object.
        let status = unsafe { NtCreateSymbolicLinkObject(&mut handle, 1, &attributes, &target) };
        if status != 0 || handle.is_null() {
            if !handle.is_null() {
                sys::close(handle);
            }
            if status.cast_unsigned() == 0xc0000035 {
                return Ok(None);
            }
            return Err(Error::Image);
        }
        Ok(Some(Self { handle, location }))
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
