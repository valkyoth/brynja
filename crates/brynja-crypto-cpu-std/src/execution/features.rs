use super::Kernel;

/// Private observations, never a public or standalone execution capability.
#[derive(Default)]
pub(super) struct Features {
    pub(super) sha: bool,
    pub(super) sse2: bool,
    pub(super) avx: bool,
    pub(super) avx2: bool,
    pub(super) neon: bool,
    pub(super) sha2: bool,
    pub(super) sha3: bool,
}

impl Features {
    pub(super) fn supports(&self, kernel: Kernel) -> bool {
        match kernel {
            Kernel::X86Sha256 => self.sha && self.sse2,
            Kernel::X86Keccak => self.avx && self.avx2,
            Kernel::ArmSha256 => self.neon && self.sha2,
            Kernel::ArmSha512 | Kernel::ArmKeccak => self.neon && self.sha3,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_128_feature_masks_require_every_prerequisite() {
        for mask in 0_u8..128 {
            let features = Features {
                sha: mask & 1 != 0,
                sse2: mask & 2 != 0,
                avx: mask & 4 != 0,
                avx2: mask & 8 != 0,
                neon: mask & 16 != 0,
                sha2: mask & 32 != 0,
                sha3: mask & 64 != 0,
            };
            for (kernel, required) in [
                (Kernel::X86Sha256, 3),
                (Kernel::X86Keccak, 12),
                (Kernel::ArmSha256, 48),
                (Kernel::ArmSha512, 80),
                (Kernel::ArmKeccak, 80),
            ] {
                assert_eq!(features.supports(kernel), mask & required == required);
            }
        }
    }
}
