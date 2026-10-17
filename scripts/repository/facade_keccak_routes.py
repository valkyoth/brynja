"""Hosted Keccak consumer source, reusing the portable lifecycle/oracle tests."""
import facade_keccak_cases as portable


def source():
    text = portable.RUST
    replacements = (
        ('let executor = batch::Executor::portable();',
         'let authority = host::keccak_batch::Authority::new(batch::Mode::Prefer).unwrap();\n'
         '            let executor = authority.executor(1).unwrap();', 1),
        ('let executor = secret::Executor::portable();',
         'let authority = host::keccak_hardened_batch::Authority::new(secret::Mode::Prefer).unwrap();\n'
         '            let executor = authority.executor(1).unwrap();', 2),
        ('assert_eq!(report.kernel, None);\n'
         '            assert_eq!(report.vector_calls, 0);\n'
         '            assert_eq!(report.vector_permutations, 0);\n'
         '            assert_eq!(report.scalar_permutations, $control.used());\n'
         '            assert!(report.scalar_permutations > 0);',
         'assert_eq!(report.kernel.is_some(), report.vector_calls > 0);\n'
         '            assert_eq!(report.vector_permutations > 0, report.vector_calls > 0);\n'
         '            assert_eq!(report.vector_permutations.checked_add(report.scalar_permutations),\n'
         '                       Some($control.used()));\n'
         '            assert!($control.used() > 0);', 1),
    )
    for before, after, count in replacements:
        if text.count(before) != count:
            raise ValueError('Keccak hosted lifecycle source anchor drift')
        text = text.replace(before, after)
    return text + COUNTERS


COUNTERS = r'''
#[cfg(test)]
mod keccak_counters {
    use super::api::sha3::{batch as b, Fips202BitString};

    #[test]
    fn static_instruction_counter_and_revocation() {
        for kernel in [b::Kernel::Avx2, b::Kernel::Neon] {
            if !kernel.compiled() {
                assert!(b::Authority::for_compiled_target(kernel).is_err());
                continue;
            }
            let authority = b::Authority::for_compiled_target(kernel).unwrap();
            let witness = authority.session().unwrap();
            assert_eq!(witness.completed_vector_calls(), 0);
            let executor = b::Executor::with_session(authority.session().unwrap(), b::Mode::Require, 1).unwrap();
            let input = b::Input::new(b::Algorithm::Sha3_256,
                Fips202BitString::new(b"abc", 8).unwrap(), 256).unwrap();
            let mut workspace = b::Workspace::new();
            let mut staging = [0; 128];
            let mut buffers = [[0xa5; 32]; 4];
            let mut cancelled = || false;
            let mut control = b::Control::new(4096, &mut cancelled);
            let report = executor.digest(b::PublicData::new(&[input; 4]),
                &mut buffers.each_mut().map(|b| b.as_mut_slice()), &mut workspace,
                &mut staging, &mut control).unwrap();
            assert!(report.vector_calls > 0);
            assert_eq!(witness.completed_vector_calls(), report.vector_calls);
            assert_eq!(report.kernel, Some(kernel));
            assert_eq!(report.vector_permutations.checked_add(report.scalar_permutations), Some(control.used()));
            // NIST SHA3-256("abc"), not another implementation in this package.
            let expected = [0x3a,0x98,0x5d,0xa7,0x4f,0xe2,0x25,0xb2,
                0x04,0x5c,0x17,0x2d,0x6b,0xd3,0x90,0xbd,0x85,0x5f,0x08,0x6e,
                0x3e,0x9d,0x52,0x5b,0x46,0xbf,0xe2,0x45,0x11,0x43,0x15,0x32];
            assert_eq!(buffers, [expected; 4]);
            let before = witness.completed_vector_calls();
            authority.quarantine();
            buffers.fill([0xa5; 32]);
            assert!(executor.digest(b::PublicData::new(&[input; 4]),
                &mut buffers.each_mut().map(|b| b.as_mut_slice()), &mut workspace,
                &mut staging, &mut b::Control::new(4096, &mut cancelled)).is_err());
            assert_eq!(buffers, [[0xa5; 32]; 4]);
            assert_eq!(witness.completed_vector_calls(), before);
        }
    }
}
'''
