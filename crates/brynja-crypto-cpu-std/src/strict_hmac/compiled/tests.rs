use super::super::tests::limits;
use super::super::{
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
    Sha512T,
};
use super::*;

fn compatibility<A: Algorithm + for<'a> brynja_mac_hmac::execution::Algorithm<'a>>(
    allowed: &[Kernel],
) {
    for kernel in Kernel::ALL {
        assert_eq!(compatible::<A>(kernel).is_ok(), allowed.contains(&kernel));
        if !allowed.contains(&kernel) || kernel.check_compiled_target().is_err() {
            assert!(matches!(
                CompiledSession::<A>::new(TagPolicy::Full, kernel, limits()),
                Err(Error::Backend(_))
            ));
        }
    }
}
#[test]
fn typed_kernel_admission_never_substitutes_a_backend() {
    let sha256 = &[Kernel::X86Sha256, Kernel::ArmSha256];
    let sha512 = &[Kernel::X86Sha512, Kernel::ArmSha512];
    let keccak = &[Kernel::X86Keccak, Kernel::ArmKeccak];
    compatibility::<Sha224>(sha256);
    compatibility::<Sha256>(sha256);
    compatibility::<Sha384>(sha512);
    compatibility::<Sha512>(sha512);
    compatibility::<Sha512_224>(sha512);
    compatibility::<Sha512_256>(sha512);
    compatibility::<Sha512T<129>>(sha512);
    compatibility::<Sha512T<511>>(sha512);
    compatibility::<Sha3_224>(keccak);
    compatibility::<Sha3_256>(keccak);
    compatibility::<Sha3_384>(keccak);
    compatibility::<Sha3_512>(keccak);
}

#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
mod native;

#[cfg(not(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
)))]
#[test]
fn accelerated_unsupported_platform_or_model_never_falls_back() {
    // No instruction entry is possible: resource admission must fail first,
    // or an unavailable compiled bundle must be rejected before that.
    for kernel in [Kernel::X86Sha256, Kernel::ArmSha256] {
        let result = CompiledSession::<Sha256>::new(TagPolicy::Full, kernel, limits());
        if kernel.check_compiled_target().is_ok() {
            assert!(matches!(
                result,
                Err(Error::Resource(crate::protected_memory::Error::Unsupported))
            ));
        } else {
            assert!(matches!(result, Err(Error::Backend(_))));
        }
    }
}
