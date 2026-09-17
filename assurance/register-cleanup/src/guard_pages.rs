//! Linux-only OS guard pages supplement bounds checks for opaque assembly,
//! which AddressSanitizer does not instrument internally.

extern crate std;

#[cfg(not(any(feature = "keccak-probe", feature = "batch256-probe")))]
use crate::kernel;
use core::ffi::{c_int, c_void};
use std::io;

#[cfg(all(
    not(any(feature = "keccak-probe", feature = "batch256-probe")),
    feature = "sha256-probe"
))]
type Word = u32;
#[cfg(all(
    not(any(feature = "keccak-probe", feature = "batch256-probe")),
    not(feature = "sha256-probe")
))]
type Word = u64;
#[cfg(all(
    not(any(feature = "keccak-probe", feature = "batch256-probe")),
    feature = "sha256-probe"
))]
const WORDS: usize = 64;
#[cfg(all(
    not(any(feature = "keccak-probe", feature = "batch256-probe")),
    not(feature = "sha256-probe")
))]
const WORDS: usize = 80;
#[cfg(not(any(feature = "keccak-probe", feature = "batch256-probe")))]
const WORD_BYTES: usize = core::mem::size_of::<Word>();
#[cfg(not(any(feature = "keccak-probe", feature = "batch256-probe")))]
const CONSTANT_BYTES: usize = WORDS * WORD_BYTES;

unsafe extern "C" {
    fn getpagesize() -> c_int;
    fn mmap(
        address: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(address: *mut c_void, length: usize, prot: c_int) -> c_int;
    fn munmap(address: *mut c_void, length: usize) -> c_int;
}

pub(super) struct Pages {
    base: *mut u8,
    page: usize,
    length: usize,
    writable: bool,
}

impl Pages {
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: Linux libc query takes no pointers or mutable state.
        let size = unsafe { getpagesize() };
        let page = usize::try_from(size).map_err(io::Error::other)?;
        if page < 704 {
            return Err(io::Error::other("page too short for fixed kernel regions"));
        }
        let length = page
            .checked_mul(3)
            .ok_or_else(|| io::Error::other("page count overflow"))?;
        // SAFETY: Request a private anonymous, inaccessible three-page mapping.
        // Linux MAP_PRIVATE=2, MAP_ANONYMOUS=32, PROT_NONE=0; no file descriptor.
        let pointer = unsafe { mmap(core::ptr::null_mut(), length, 0, 2 | 32, -1, 0) };
        if pointer as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        let pages = Self {
            base: pointer.cast(),
            page,
            length,
            writable: true,
        };
        if pages.base.is_null() {
            return Err(io::Error::other("null mapping cannot back Rust references"));
        }
        // SAFETY: The middle whole page lies within this exact live mapping.
        // Linux PROT_READ|PROT_WRITE=3. Surrounding pages stay inaccessible.
        if unsafe { mprotect(pages.base.add(page).cast(), page, 3) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pages)
    }

    pub(super) fn bytes<const N: usize>(&mut self, at_end: bool) -> &mut [u8; N] {
        assert!(
            self.writable,
            "cannot create a mutable borrow of a read-only page"
        );
        assert!(N <= self.page);
        let offset = if at_end { self.page - N } else { 0 };
        // SAFETY: The checked N-byte range lies wholly in the initialized,
        // writable middle page. The exclusive self borrow prevents aliasing.
        unsafe { &mut *self.base.add(self.page + offset).cast::<[u8; N]>() }
    }

    pub(super) fn readonly(&mut self) -> io::Result<()> {
        // SAFETY: No borrow escapes this method. This live middle page changes
        // to PROT_READ=1 before any shared reference is passed to the kernel.
        if unsafe { mprotect(self.base.add(self.page).cast(), self.page, 1) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.writable = false;
        Ok(())
    }

    pub(super) fn read<const N: usize>(&self, at_end: bool) -> &[u8; N] {
        assert!(N <= self.page);
        let offset = if at_end { self.page - N } else { 0 };
        // SAFETY: The exact checked range is initialized and readable; shared
        // borrowing cannot mutate it. The mapping stays live until Drop.
        unsafe { &*self.base.add(self.page + offset).cast::<[u8; N]>() }
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: This object uniquely owns this entire exact mmap allocation.
        let result = unsafe { munmap(self.base.cast(), self.length) };
        assert_eq!(result, 0, "guard-page mapping could not be released");
    }
}

#[test]
#[cfg(not(any(feature = "keccak-probe", feature = "batch256-probe")))]
#[cfg_attr(
    all(
        not(feature = "sha256-probe"),
        not(any(
            all(
                target_arch = "x86_64",
                target_feature = "sha512",
                target_feature = "avx2",
                target_feature = "avx"
            ),
            all(
                target_arch = "aarch64",
                target_feature = "neon",
                target_feature = "sha3"
            )
        ))
    ),
    ignore = "requires dedicated SHA512 CPU or Intel SDE and the complete build feature bundle"
)]
#[cfg_attr(
    all(
        feature = "sha256-probe",
        not(any(
            all(
                target_arch = "x86_64",
                target_feature = "sha",
                target_feature = "sse2"
            ),
            all(
                target_arch = "aarch64",
                target_feature = "neon",
                target_feature = "sha2"
            )
        ))
    ),
    ignore = "requires SHA/SSE2 or NEON/SHA2 with the complete build feature bundle"
)]
fn inaccessible_edges_and_readonly_inputs() -> io::Result<()> {
    #[cfg(feature = "sha256-probe")]
    let available = cfg!(any(
        all(
            target_arch = "x86_64",
            target_feature = "sha",
            target_feature = "sse2"
        ),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha2"
        )
    ));
    #[cfg(not(feature = "sha256-probe"))]
    let available = cfg!(any(
        all(
            target_arch = "x86_64",
            target_feature = "sha512",
            target_feature = "avx2",
            target_feature = "avx"
        ),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha3"
        )
    ));
    assert!(core::hint::black_box(available));
    for placement in 0..16 {
        let mut state = Pages::new()?;
        let mut block = Pages::new()?;
        let mut scratch = Pages::new()?;
        let mut constants = Pages::new()?;
        let state_end = placement & 1 != 0;
        let block_end = placement & 2 != 0;
        let scratch_end = placement & 4 != 0;
        let constants_end = placement & 8 != 0;
        state.bytes::<64>(state_end).fill(0xa5);
        block.bytes::<128>(block_end).fill(0x5a);
        scratch.bytes::<704>(scratch_end).fill(0x5c);
        for (slot, value) in constants
            .bytes::<CONSTANT_BYTES>(constants_end)
            .as_chunks_mut::<WORD_BYTES>()
            .0
            .iter_mut()
            .zip(crate::constants::ROUND_CONSTANTS)
        {
            *slot = value.to_ne_bytes();
        }
        block.readonly()?;
        constants.readonly()?;
        let initial = *state.read::<64>(state_end);
        let input = *block.read::<128>(block_end);
        let expected = crate::tests::reference(initial, &input);
        let constant_bytes = constants.read::<CONSTANT_BYTES>(constants_end);
        assert_eq!(
            constant_bytes
                .as_ptr()
                .align_offset(core::mem::align_of::<Word>()),
            0
        );
        // SAFETY: This complete aligned initialized range contains exactly
        // WORDS native-endian Word constants and remains read-only.
        let words = unsafe { &*constant_bytes.as_ptr().cast::<[Word; WORDS]>() };
        // SAFETY: The explicit ISA test precondition holds. Four distinct
        // mappings enforce exclusive outputs and truly read-only inputs.
        unsafe {
            kernel::compress(
                state.bytes(state_end),
                block.read(block_end),
                scratch.bytes(scratch_end),
                words,
            );
        }
        assert_eq!(*state.read::<64>(state_end), expected);
        assert_eq!(*block.read::<128>(block_end), input);
        assert_eq!(*scratch.read::<704>(scratch_end), [0; 704]);
    }
    std::println!("REGISTER_BOUNDS: 16 guarded placements; readonly input/constants: PASS");
    Ok(())
}
