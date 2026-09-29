//! Fixed public-vector experiment for scoped result lifetimes.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

mod sha256_vectors;
use brynja_core::{SecretRegionInitialization, clear_owned_region};
use brynja_hash_sha2::hardened_in_place::Sha256Workspace;
use enclave_result::{Error, Issuer, PUBLIC_OUTPUT};

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
    let mut issuer = Issuer::new(0x4252594e).ok()?;
    let mut template = [0_u8; 1024];
    let (mut comparisons, mut lifecycles) = (0_usize, 0_usize);
    for (case, expected) in sha256_vectors::EXPECTED.iter().enumerate() {
        let length = fill(case, &mut template)?;
        for _ in 0..if mode == 0 { 2 } else { 1 } {
            let mut init = SecretRegionInitialization::begin(&mut buffers.input).ok()?;
            init.write(&template).ok()?;
            let input = init.finish().ok()?;
            let destination: &mut [u8; 32] = (&mut buffers.output[..32]).try_into().ok()?;
            let success = issuer
                .sha256(
                    workspace,
                    destination,
                    &input.expose()[..length],
                    |handle| {
                        let token = handle.token();
                        let mut writes = 0;
                        let mut equal = false;
                        let result = match mode {
                            0 => handle.export_public(token, PUBLIC_OUTPUT, |bytes| {
                                writes += 1;
                                equal = bytes == expected;
                                true
                            }),
                            1 if case % 2 == 0 => handle.cancel(token),
                            1 => return true, // Abandonment clears independently at scope exit.
                            2 => handle.export_public(
                                if case % 2 == 0 { [token[0], 0] } else { token },
                                if case % 2 == 0 { PUBLIC_OUTPUT } else { 0 },
                                |_| {
                                    writes += 1;
                                    true
                                },
                            ),
                            3 => handle.export_public(token, PUBLIC_OUTPUT, |bytes| {
                                writes += 1;
                                equal = bytes == expected;
                                false // Internal copy-failure simulation, not a host write.
                            }),
                            _ => return false,
                        };
                        let expected_result = match mode {
                            0 | 1 => Ok(()),
                            2 => Err(Error::Rejected),
                            _ => Err(Error::Copy),
                        };
                        if result != expected_result
                            || writes != usize::from(mode == 0 || mode == 3)
                            || ((mode == 0 || mode == 3) && !equal)
                        {
                            return false;
                        }
                        let mut replayed = false;
                        let replay = handle.export_public(token, PUBLIC_OUTPUT, |_| {
                            replayed = true;
                            true
                        });
                        replay == Err(Error::Spent) && !replayed
                    },
                )
                .ok()?;
            if !success || !workspace_zero(workspace) || !zero(&buffers.output) {
                return None;
            }
            drop(input);
            if !zero(&buffers.input) {
                return None;
            }
            lifecycles = lifecycles.checked_add(1)?;
            if mode == 0 {
                comparisons = comparisons.checked_add(1)?;
            }
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
