"""Sole-source corpus relocation and public SHA-2 capability probing."""
PROBE = r'''
#![forbid(unsafe_code)]
use brynja_crypto_cpu::static_execution as raw;
use brynja_crypto_cpu_std::execution as host;
fn main() {
    let (mut narrow, mut wide) = (false, false);
    #[cfg(target_arch = "x86_64")] {
        narrow = std::arch::is_x86_feature_detected!("sha") && std::arch::is_x86_feature_detected!("sse2");
        wide = std::arch::is_x86_feature_detected!("sha512") && std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("avx");
    }
    #[cfg(target_arch = "aarch64")] {
        narrow = std::arch::is_aarch64_feature_detected!("neon") && std::arch::is_aarch64_feature_detected!("sha2");
        wide = std::arch::is_aarch64_feature_detected!("neon") && std::arch::is_aarch64_feature_detected!("sha3");
    }
    println!("ARCH:{}", std::env::consts::ARCH);
    println!("CPU:narrow:{narrow}");
    println!("CPU:wide:{wide}");
    let kernels = if cfg!(target_arch = "x86_64") { [raw::Kernel::X86Sha256, raw::Kernel::X86Sha512] }
                  else { [raw::Kernel::ArmSha256, raw::Kernel::ArmSha512] };
    for (name, kernel) in ["narrow", "wide"].into_iter().zip(kernels) {
        match raw::Authority::new(kernel) {
            Ok(a) => { assert_eq!(a.report().health, raw::Health::Healthy); println!("STATIC:{name}:ready"); }
            Err(e @ (raw::Error::MissingTargetFeatures | raw::Error::WrongArchitecture)) => println!("STATIC:{name}:{e:?}"),
            Err(e) => panic!("static integrity failure: {e:?}"),
        }
        match host::Authority::new(kernel, host::Mode::Require) {
            Ok(a) => { assert_eq!(a.report().health, Some(raw::Health::Healthy)); assert!(a.session().unwrap().is_some()); println!("HOST:{name}:ready"); }
            Err(host::Error::Unavailable(e)) => println!("HOST:{name}:{e:?}"),
            Err(e) => panic!("host integrity failure: {e:?}"),
        }
    }
}
'''


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('SHA-2 consumer source anchor drift')
    return text.replace(before, after)


def corpus(text):
    # Reuse the original bounded visitor, not a second oracle or algorithm.
    # Omit only its unused convenience callback and retain both parser tests.
    text = once(text, 'use crate::acceptance::{Error, check_case};', 'use crate::acceptance::Error;')
    text = once(text, 'pub(crate) fn run(corpus: &str) -> Result<usize, Error> {\n    visit(corpus, check_case)\n}\n', '')
    return once(text, 'assert!(run(input).is_err());', 'assert!(visit(input, |_, _, _, _| Ok(())).is_err());')


ERROR = '''#[derive(Debug)]
pub enum Error { Corpus, Mismatch }
'''
