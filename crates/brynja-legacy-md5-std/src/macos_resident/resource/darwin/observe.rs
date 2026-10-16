//! Native test-only SDK observations; never production admission or crypto.
#![allow(unsafe_code)]
use super::{Error, Mapping};

// mach/vm_region.h packs public Mach structures to four-byte alignment.
#[repr(C, packed(4))]
struct Info {
    protection: i32,
    maximum: i32,
    inheritance: i32,
    shared: i32,
    reserved: i32,
    offset: u64,
    behavior: i32,
    wired: u16,
}
const _: () = assert!(core::mem::size_of::<Info>() == 36);
pub(super) fn verify(mapping: &Mapping) -> Result<(), Error> {
    let data = mapping.data.as_ptr() as u64;
    let mut address = data;
    let mut size = 0u64;
    let mut count = 9u32;
    let mut object = 0u32;
    let mut info = Info {
        protection: 0,
        maximum: 0,
        inheritance: 0,
        shared: 0,
        reserved: 0,
        offset: 0,
        behavior: 0,
        wired: 0,
    };
    // SAFETY: current task; valid writable outputs and exactly nine 32-bit words
    // in the SDK-compatible basic-info structure. No region contents are read.
    let status = unsafe {
        mach_vm_region(
            super::mach_task_self_,
            &mut address,
            &mut size,
            9,
            core::ptr::from_mut(&mut info).cast(),
            &mut count,
            &mut object,
        )
    };
    if object != 0 {
        super::check(
            // SAFETY: region call returned one owned object send right in current task.
            unsafe { mach_port_deallocate(super::mach_task_self_, object) },
            Error::Invariant,
        )?;
    }
    super::check(status, Error::Invariant)?;
    assert_eq!(count, 9);
    assert!(
        address <= data
            && address.checked_add(size).is_some_and(|end| data
                .checked_add(mapping.layout.payload as u64)
                .is_some_and(|limit| end >= limit))
    );
    assert!(info.protection == 3 && info.inheritance == 2 && info.wired > 0);
    let base = mapping.base.ok_or(Error::Invariant)?.as_ptr() as u64;
    let upper = data
        .checked_add(mapping.layout.payload as u64)
        .ok_or(Error::Invariant)?;
    for (source, readable) in [(base, false), (data, true), (upper, false)] {
        let mut output = 0u8;
        let mut actual = 0u64;
        // SAFETY: kernel-mediated read of our mapping; invalid guard addresses
        // return an error without a Rust dereference. Destination holds one byte.
        let result = unsafe {
            mach_vm_read_overwrite(
                super::mach_task_self_,
                source,
                1,
                core::ptr::from_mut(&mut output) as u64,
                &mut actual,
            )
        };
        assert_eq!(result == 0 && actual == 1, readable);
    }
    Ok(())
}
unsafe extern "C" {
    fn mach_vm_region(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
        object: *mut u32,
    ) -> i32;
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
    fn mach_vm_read_overwrite(
        task: u32,
        source: u64,
        size: u64,
        destination: u64,
        actual: *mut u64,
    ) -> i32;
}
