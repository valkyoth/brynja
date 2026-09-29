//! Fixed public-vector experiment for existing in-place hardened ownership.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

mod sha256_vectors;
use brynja_core::{SecretRegionInitialization, clear_owned_region};
use brynja_hash_sha2::{HardenedSha2Error, hardened_in_place::Sha256Workspace};

// The build tool checks the complete byte-array-only source layout. Equality of
// aggregate size and field-size sum excludes padding in this specific fixture.
const OWNER_BYTES: usize = 1170;
const _: () = assert!(core::mem::size_of::<Sha256Workspace>() == OWNER_BYTES);
const _: () = assert!(core::mem::align_of::<Sha256Workspace>() == 1);

#[repr(C)]
pub struct Report {
    status: usize,
    input: usize,
    workspace: usize,
    output: usize,
    comparisons: usize,
    lifecycles: usize,
    cleared: usize,
    workspace_size: usize,
}

#[cfg(not(test))]
unsafe extern "C" {
    fn PublicProbeAbort() -> !;
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: experiment-only non-returning C adapter; panic is fatal failure.
    unsafe { PublicProbeAbort() }
}

fn zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0, |acc, byte| {
        // SAFETY: shared reference to an initialized byte, no concurrent writer.
        acc | unsafe { core::ptr::read_volatile(byte) }
    }) == 0
}

fn workspace_zero(workspace: &Sha256Workspace) -> bool {
    // SAFETY: this SOURCE-BOUND experiment verifies that the workspace consists
    // exclusively of initialized byte arrays and a zero-sized PhantomData.
    // Size/alignment are compile-time checked above; no padding exists. The
    // shared reference is live and no scoped mutable handle exists here.
    // This is not a general-purpose opaque-object inspection API.
    let bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::from_ref(workspace).cast::<u8>(), OWNER_BYTES)
    };
    zero(bytes)
}

struct Buffers {
    input: [u8; 1024],
    output: [u8; 33],
}
impl Buffers {
    fn clear(&mut self) {
        let _ = clear_owned_region(&mut self.input);
        let _ = clear_owned_region(&mut self.output);
    }
}
impl Drop for Buffers {
    fn drop(&mut self) {
        self.clear();
    }
}

fn fill(case: usize, template: &mut [u8; 1024]) -> Option<usize> {
    const TEXT: [&[u8]; 4] = [b"", b"abc",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"];
    let length = *sha256_vectors::LENGTHS.get(case)?;
    for (index, byte) in template.iter_mut().enumerate() {
        *byte = ((index % 256) as u8)
            .wrapping_mul(17)
            .wrapping_add(case as u8);
    }
    if let Some(text) = TEXT.get(case) {
        template.get_mut(..length)?.copy_from_slice(text);
    }
    Some(length)
}

fn campaign(
    workspace: &mut Sha256Workspace,
    buffers: &mut Buffers,
    mode: usize,
) -> Option<(usize, usize)> {
    let mut comparisons = 0_usize;
    let mut lifecycles = 0_usize;
    // Source is PUBLIC test material. This is not a host-to-enclave secret-input
    // interface; no host pointer, callback, key or confidential input is accepted.
    let mut template = [0_u8; 1024];
    for (case, expected) in sha256_vectors::EXPECTED.iter().enumerate() {
        let length = fill(case, &mut template)?;
        for step in if mode == 0 { &[1024, 7][..] } else { &[7][..] } {
            let mut initialization = SecretRegionInitialization::begin(&mut buffers.input).ok()?;
            initialization.write(&template).ok()?;
            let input = initialization.finish().ok()?;
            if mode == 0 {
                let output = workspace
                    .with(|mut state| {
                        state.update(&[])?;
                        for chunk in input.expose()[..length].chunks(*step) {
                            state.update(chunk)?;
                        }
                        state.finalize_secret(&mut buffers.output[..32])
                    })
                    .ok()?;
                if !workspace_zero(workspace) {
                    return None;
                }
                let equal = output.expose() == expected;
                if cfg!(probe_forget_output) {
                    core::mem::forget(output);
                } else {
                    drop(output);
                }
                if !zero(&buffers.output) || !equal || cfg!(probe_wrong_digest) {
                    return None;
                }
                comparisons = comparisons.checked_add(1)?;
            } else {
                if mode == 2 {
                    buffers.output.fill(0xa5);
                }
                let result = workspace.with(|mut state| {
                    for chunk in input.expose()[..length].chunks(*step) {
                        state.update(chunk)?;
                    }
                    match mode {
                        1 => state.cancel(),
                        2 => {
                            if !matches!(
                                state.finalize_secret(&mut buffers.output),
                                Err(HardenedSha2Error::OutputLength)
                            ) {
                                return Err(HardenedSha2Error::StateConsumed);
                            }
                        }
                        3 => core::mem::forget(state),
                        _ => return Err(HardenedSha2Error::StateConsumed),
                    }
                    Ok(())
                });
                if result.is_err() || !workspace_zero(workspace) || !zero(&buffers.output) {
                    return None;
                }
            }
            drop(input);
            if !zero(&buffers.input) {
                return None;
            }
            lifecycles = lifecycles.checked_add(1)?;
        }
    }
    Some((comparisons, lifecycles))
}

fn within(address: usize, size: usize, low: usize, high: usize) -> bool {
    address >= low && address.checked_add(size).is_some_and(|end| end <= high)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn PublicHardenedWork(mode: usize, low: usize, high: usize) -> Report {
    let mut report = Report {
        status: 0,
        input: 0,
        workspace: 0,
        output: 0,
        comparisons: 0,
        lifecycles: 0,
        cleared: 0,
        workspace_size: OWNER_BYTES,
    };
    if mode > 3 || high.checked_sub(low) != Some(65536) {
        return report;
    }
    let mut workspace = Sha256Workspace::new();
    let mut buffers = Buffers {
        input: [0; 1024],
        output: [0; 33],
    };
    report.input = buffers.input.as_ptr() as usize;
    report.output = buffers.output.as_ptr() as usize;
    report.workspace = core::ptr::from_ref(&workspace) as usize;
    if !within(report.input, 1024, low, high)
        || !within(report.output, 33, low, high)
        || !within(report.workspace, OWNER_BYTES, low, high)
    {
        return report;
    }
    let result = campaign(&mut workspace, &mut buffers, mode);
    // This second guard does not turn failed inner ownership checks into passes.
    buffers.clear();
    report.cleared =
        usize::from(zero(&buffers.input) && zero(&buffers.output) && workspace_zero(&workspace));
    if let Some((comparisons, lifecycles)) = result {
        report.comparisons = comparisons;
        report.lifecycles = lifecycles;
        if report.cleared == 1 {
            report.status = mode + 1;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_ownership_modes() {
        for (mode, comparisons, lifecycles) in [(0, 40, 40), (1, 0, 20), (2, 0, 20), (3, 0, 20)] {
            let mut workspace = Sha256Workspace::new();
            let mut buffers = Buffers {
                input: [0; 1024],
                output: [0; 33],
            };
            assert_eq!(
                campaign(&mut workspace, &mut buffers, mode),
                Some((comparisons, lifecycles))
            );
            assert!(workspace_zero(&workspace));
            assert!(zero(&buffers.input) && zero(&buffers.output));
        }
    }
    #[test]
    fn root_guard_clears_forgotten_output_storage() {
        let mut buffers = Buffers {
            input: [0xa5; 1024],
            output: [0xa5; 33],
        };
        buffers.clear();
        assert!(zero(&buffers.input) && zero(&buffers.output));
    }
    #[test]
    fn layout_and_bounds() {
        assert_eq!(core::mem::size_of::<Report>(), 64);
        assert_eq!(core::mem::align_of::<Report>(), 8);
        assert_eq!(core::mem::offset_of!(Report, workspace_size), 56);
        assert!(within(100, 32, 100, 132));
        assert!(!within(99, 32, 100, 132));
        assert!(!within(100, 33, 100, 132));
        assert!(!within(usize::MAX, 1, 0, usize::MAX));
        for (mode, low, high) in [(4, 0, 65536), (0, 2, 1), (0, 0, 0)] {
            let report = PublicHardenedWork(mode, low, high);
            assert_eq!(
                (
                    report.status,
                    report.comparisons,
                    report.lifecycles,
                    report.cleared
                ),
                (0, 0, 0, 0)
            );
        }
    }
}
