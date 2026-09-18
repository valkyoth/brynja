//! Source-bound MD5 transfer probe; this mirror is not a clearing owner.
#![no_std]

#[derive(Debug, PartialEq, Eq)]
pub enum Md5BackendError {
    Quarantined,
}

#[allow(dead_code)]
mod scratch {
    #[repr(C)]
    pub struct Scratch {
        pub initial: [[u8; 32]; 4],
        pub words: [[u8; 32]; 16],
        pub work: [[u8; 32]; 4],
        pub temporary: [[u8; 32]; 3],
    }
    impl Scratch {
        pub const fn new() -> Self {
            Self {
                initial: [[0; 32]; 4],
                words: [[0; 32]; 16],
                work: [[0; 32]; 4],
                temporary: [[0; 32]; 3],
            }
        }
    }
}

#[allow(dead_code)]
#[path = "../../../../crates/brynja-legacy-md5/src/cpu/transfer.rs"]
mod actual;

pub type Probe = unsafe extern "C" fn(*mut u8, *const u8, usize);
pub static PROBES: [Probe; 4] = [
    actual::transpose::<4, true>,
    actual::transpose::<16, true>,
    actual::transpose::<4, false>,
    actual::transpose::<32, true>,
];

#[cfg(test)]
mod tests;
