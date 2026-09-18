//! Linux-only OS guard pages supplement bounds checks for opaque assembly,
//! which AddressSanitizer does not instrument internally.

extern crate std;

#[cfg(not(any(
    feature = "keccak-probe",
    feature = "batch256-probe",
    feature = "batch512-probe",
    feature = "keccak-batch-probe"
)))]
use crate::kernel;
#[cfg(not(any(
    feature = "keccak-probe",
    feature = "batch256-probe",
    feature = "batch512-probe",
    feature = "keccak-batch-probe"
)))]
use std::io;

#[cfg(all(
    not(any(
        feature = "keccak-probe",
        feature = "batch256-probe",
        feature = "batch512-probe",
        feature = "keccak-batch-probe"
    )),
    feature = "sha256-probe"
))]
type Word = u32;
#[cfg(all(
    not(any(
        feature = "keccak-probe",
        feature = "batch256-probe",
        feature = "batch512-probe",
        feature = "keccak-batch-probe"
    )),
    not(feature = "sha256-probe")
))]
type Word = u64;
#[cfg(all(
    not(any(
        feature = "keccak-probe",
        feature = "batch256-probe",
        feature = "batch512-probe",
        feature = "keccak-batch-probe"
    )),
    feature = "sha256-probe"
))]
const WORDS: usize = 64;
#[cfg(all(
    not(any(
        feature = "keccak-probe",
        feature = "batch256-probe",
        feature = "batch512-probe",
        feature = "keccak-batch-probe"
    )),
    not(feature = "sha256-probe")
))]
const WORDS: usize = 80;
#[cfg(not(any(
    feature = "keccak-probe",
    feature = "batch256-probe",
    feature = "batch512-probe",
    feature = "keccak-batch-probe"
)))]
const WORD_BYTES: usize = core::mem::size_of::<Word>();
#[cfg(not(any(
    feature = "keccak-probe",
    feature = "batch256-probe",
    feature = "batch512-probe",
    feature = "keccak-batch-probe"
)))]
const CONSTANT_BYTES: usize = WORDS * WORD_BYTES;

#[path = "guard_memory.rs"]
mod memory;
pub(super) use memory::Pages;
#[test]
#[cfg(not(any(
    feature = "keccak-probe",
    feature = "batch256-probe",
    feature = "batch512-probe",
    feature = "keccak-batch-probe"
)))]
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
