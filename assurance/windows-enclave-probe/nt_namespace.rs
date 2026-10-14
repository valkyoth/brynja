// Native test-only object-manager alias attempt in a disposable logon session.
// No permanent objects, global namespace modification or production ABI change.
mod nt_shadow {
    use core::ffi::c_void;
    type Handle = *mut c_void;
    #[repr(C)]
    struct Unicode { length: u16, maximum: u16, buffer: *const u16 }
    #[repr(C)]
    struct Attributes {
        length: u32, root: Handle, name: *const Unicode, flags: u32,
        security: *const c_void, quality: *const c_void,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtOpenDirectoryObject(out: *mut Handle, access: u32, attr: *mut Attributes) -> i32;
        fn NtCreateSymbolicLinkObject(out: *mut Handle, access: u32, attr: *const Attributes,
                                     target: *const Unicode) -> i32;
        fn NtQueryObject(handle: Handle, class: u32, out: *mut c_void, size: u32,
                         needed: *mut u32) -> i32;
        fn NtClose(handle: Handle) -> i32;
    }
    fn string(buffer: &mut [u16]) -> Unicode {
        let bytes = u16::try_from(buffer.len().checked_mul(2).unwrap()).unwrap();
        Unicode { length: bytes, maximum: bytes, buffer: buffer.as_mut_ptr() }
    }
    fn attributes(root: Handle, name: &mut Unicode) -> Attributes {
        Attributes { length: 48, root, name, flags: 0x40,
                     security: core::ptr::null_mut(), quality: core::ptr::null_mut() }
    }
    struct Owned(Handle);
    impl Drop for Owned {
        fn drop(&mut self) { assert_eq!(unsafe { NtClose(self.0) }, 0); }
    }
    fn object_name(handle: Handle) -> String {
        let mut data = [0usize; 512];
        let mut needed = 0;
        assert_eq!(unsafe { NtQueryObject(handle, 1, data.as_mut_ptr().cast(),
                                         4096, &mut needed) }, 0);
        assert!(needed >= 16 && needed <= 4096);
        let name = unsafe { &*data.as_ptr().cast::<Unicode>() };
        assert_eq!(name.length % 2, 0);
        let base = data.as_ptr() as usize;
        let start = name.buffer as usize;
        assert!(start >= base + 16 && start % 2 == 0);
        assert!(start.checked_add(usize::from(name.length)).unwrap() <= base + needed as usize);
        String::from_utf16(unsafe { core::slice::from_raw_parts(name.buffer, usize::from(name.length) / 2) }).unwrap()
    }
    fn create(directory: Handle, name: &str, target: &str) -> (i32, Option<Owned>) {
        let mut name: Vec<u16> = name.encode_utf16().collect();
        let mut target: Vec<u16> = target.encode_utf16().collect();
        let mut name = string(&mut name);
        let mut target = string(&mut target);
        let mut attr = attributes(directory, &mut name);
        let mut handle = core::ptr::null_mut();
        let status = unsafe { NtCreateSymbolicLinkObject(&mut handle, 0xf0001, &mut attr, &mut target) };
        let owned = if status >= 0 { assert!(!handle.is_null()); Some(Owned(handle)) }
                    else { assert!(handle.is_null()); None };
        (status, owned)
    }
    pub struct Shadow { pub path: String, _link: Option<Owned>, _directory: Owned }
    pub fn preclaimed(rejected: impl FnOnce() -> bool) {
        let name = format!(r"\??\BrynjaImage-{}-0.dll", std::process::id());
        let (status, owner) = create(core::ptr::null_mut(), &name, r"\");
        assert_eq!(status, 0);
        assert!(rejected(), "preclaimed loader alias was accepted");
        let (status, duplicate) = create(core::ptr::null_mut(), &name, r"\");
        assert_eq!(status as u32, 0xc0000035, "rejection disturbed preexisting alias");
        assert!(duplicate.is_none());
        drop(owner);
        println!("NT_ALIAS: preclaimed-name rejected; preexisting object retained");
    }
    pub fn held_alias(path: &std::ffi::OsStr) {
        let alias = path.to_str().unwrap().strip_prefix(r"\\?\").unwrap();
        assert!(alias.starts_with("BrynjaImage-"));
        let (status, owned) = create(core::ptr::null_mut(), &format!(r"\??\{alias}"), r"\");
        assert_eq!(status as u32, 0xc0000035, "held loader alias was replaceable");
        assert!(owned.is_none());
        println!("NT_ALIAS: held-name collision rejected");
    }
    pub fn released_alias(path: &std::ffi::OsStr) {
        let alias = path.to_str().unwrap().strip_prefix(r"\\?\").unwrap();
        let (status, owned) = create(core::ptr::null_mut(), &format!(r"\??\{alias}"), r"\");
        assert_eq!(status, 0, "temporary loader alias leaked after Drop");
        drop(owned);
        println!("NT_ALIAS: retired-name recreated and removed");
    }
    impl Shadow {
        pub fn globalroot(canonical: &std::ffi::OsStr, replacement: &str) -> Self {
            assert_eq!(core::mem::size_of::<Unicode>(), 16);
            assert_eq!(core::mem::size_of::<Attributes>(), 48);
            let suffix = canonical.to_str().unwrap().strip_prefix(r"\\?\GLOBALROOT\").unwrap();
            let redirected = std::path::Path::new(replacement).join(suffix);
            std::fs::create_dir_all(redirected.parent().unwrap()).unwrap();
            std::fs::write(&redirected, b"globalroot-redirected").unwrap();
            let mut name: Vec<u16> = r"\??".encode_utf16().collect();
            let mut name = string(&mut name);
            let mut attr = attributes(core::ptr::null_mut(), &mut name);
            let mut directory = core::ptr::null_mut();
            assert_eq!(unsafe { NtOpenDirectoryObject(&mut directory, 5, &mut attr) }, 0);
            assert!(!directory.is_null());
            let directory = Owned(directory);
            let actual = object_name(directory.0);
            // Never create aliases in the global namespace, even on test hosts.
            assert!(actual.starts_with(r"\Sessions\") && actual.contains(r"\DosDevices\"),
                    "not a per-logon directory: {actual}");
            println!("NT_DIRECTORY: {actual}");
            let target = format!(r"\??\{replacement}");
            let (status, control) = create(directory.0, "BrynjaNtControl", &target);
            assert_eq!(status, 0);
            assert_eq!(std::fs::read(format!(r"\\?\BrynjaNtControl\{suffix}")).unwrap(), b"globalroot-redirected");
            drop(control);
            assert!(std::fs::read(format!(r"\\?\BrynjaNtControl\{suffix}")).is_err());
            println!("NT_CONTROL: redirected; handle-close=removed");
            let (status, link) = create(directory.0, "GLOBALROOT", &target);
            assert!(status == 0 || matches!(status as u32, 0xc0000022 | 0xc0000035),
                    "unexpected NT status: {:08x}", status as u32);
            println!("GLOBALROOT_SHADOW: direct-nt; created={}; status={:08x}", link.is_some(), status as u32);
            Self { path: redirected.to_str().unwrap().to_owned(), _link: link, _directory: directory }
        }
    }
}
