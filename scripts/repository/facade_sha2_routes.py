"""Synthetic downstream route/lifecycle tests, using only facade and host APIs."""

PROBE = r'''
#![forbid(unsafe_code)]
fn main() {
    let mut cpu = "none";
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx2") { cpu = "avx2"; }
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("neon") { cpu = "neon"; }
    println!("CPU:{cpu}");
    macro_rules! route {
        ($module:ident, $name:literal) => {{
            use host::$module::{Authority, Error, Mode};
            let available = match Authority::new(Mode::Require) {
                Ok(a) => { assert!(a.kernel().unwrap().is_some()); true }
                Err(Error::Unavailable) => false,
                Err(error) => panic!("unexpected authority failure: {error:?}"),
            };
            println!("ROUTE:{}:{}", $name, available);
        }};
    }
    route!(sha256_batch, "sha256-batch");
    route!(sha512_batch, "sha512-batch");
    route!(sha256_hardened_batch, "hardened-sha256-batch");
    route!(sha512_hardened_batch, "hardened-sha512-batch");
}
'''

RUST = r'''
#[cfg(test)]
mod routes {
    use super::api;
    macro_rules! ordinary {
        ($name:ident, $module:ident, $host:ident, $algorithm:ident, $reference:ident) => {
            #[test]
            fn $name() {
                use api::sha2::$module as batch;
                use host::$host::{Authority, Error};
                let message = [7; 256];
                let bits = api::sha2::BitString::new(&message, 8).unwrap();
                let inputs = [Some(batch::Input::new(batch::Algorithm::$algorithm, bits)); batch::CAPACITY];
                let expected = batch::Digest::$algorithm(api::sha2::$reference(&message).unwrap());
                for mode in [batch::Mode::Portable, batch::Mode::Prefer, batch::Mode::Require] {
                    let authority = match Authority::new(mode) {
                        Ok(a) => a,
                        Err(Error::Unavailable) => { assert_eq!(mode, batch::Mode::Require); continue; }
                        Err(e) => panic!("authority failure: {e:?}"),
                    };
                    let kernel = authority.kernel().unwrap();
                    if mode == batch::Mode::Portable { assert!(kernel.is_none()); }
                    let executor = authority.executor(1).unwrap();
                    for phase in 0..4 {
                        let mut output = [Some(expected); batch::CAPACITY];
                        let mut cancelled = || phase == 2;
                        let mut control = batch::Control::new(if phase == 1 { 0 } else { 1024 }, &mut cancelled);
                        let result = executor.digest(batch::PublicData::new(&inputs), &mut output, &mut control);
                        if phase == 1 || phase == 2 { assert!(result.is_err()); }
                        else {
                            let report = result.unwrap();
                            assert_eq!(report.kernel, kernel);
                            assert_eq!(report.vector_calls > 0, kernel.is_some());
                            assert_eq!(report.vector_blocks.checked_add(report.scalar_blocks), Some(control.used()));
                        }
                        assert_eq!(output, [Some(expected); batch::CAPACITY]);
                    }
                    if kernel.is_some() {
                        let authority = Authority::new(mode).unwrap();
                        let other = authority.executor(1).unwrap();
                        authority.quarantine();
                        assert!(authority.kernel().is_err());
                        let mut output = [Some(expected); batch::CAPACITY];
                        let mut cancelled = || false;
                        assert!(other.digest(batch::PublicData::new(&inputs), &mut output,
                            &mut batch::Control::new(1024, &mut cancelled)).is_err());
                        assert_eq!(output, [Some(expected); batch::CAPACITY]);
                    }
                }
            }
        };
    }
    macro_rules! secret {
        ($name:ident, $module:ident, $host:ident, $algorithm:ident, $reference:ident, $width:literal) => {
            #[test]
            fn $name() {
                use api::sha2::$module as batch;
                use host::$host::{Authority, Error};
                let message = [7; 256];
                let bits = api::sha2::BitString::new(&message, 8).unwrap();
                let inputs = core::array::from_fn(|_| Some(batch::Input::new(batch::Algorithm::$algorithm, bits)));
                let expected = api::sha2::$reference(&message).unwrap();
                for mode in [batch::Mode::Portable, batch::Mode::Prefer, batch::Mode::Require] {
                    let authority = match Authority::new(mode) {
                        Ok(a) => a,
                        Err(Error::Unavailable) => { assert_eq!(mode, batch::Mode::Require); continue; }
                        Err(e) => panic!("authority failure: {e:?}"),
                    };
                    let kernel = authority.kernel().unwrap();
                    if mode == batch::Mode::Portable { assert!(kernel.is_none()); }
                    let executor = authority.executor(1).unwrap();
                    let mut workspace = batch::Workspace::new();
                    for phase in 0..5 {
                        let mut output = [[0xa5; $width + 1]; batch::CAPACITY];
                        let mut cancelled = || phase == 2;
                        let mut control = batch::Control::new(if phase == 1 { 0 } else { 1024 }, &mut cancelled);
                        if phase == 4 { executor.quarantine(); }
                        {
                            let result = executor.digest_secret(&inputs,
                                output.each_mut().map(|b| Some(&mut b[..$width])), &mut workspace, &mut control);
                            if phase == 1 || phase == 2 || phase == 4 { assert!(result.is_err()); }
                            else {
                                let (owned, report) = result.unwrap();
                                assert_eq!(report.kernel, kernel);
                                assert_eq!(report.vector_calls > 0, kernel.is_some());
                                assert_eq!(report.vector_blocks.checked_add(report.scalar_blocks), Some(control.used()));
                                for i in 0..batch::CAPACITY {
                                    assert_eq!(owned.expose(i), Some(expected.as_bytes().as_slice()));
                                    assert_eq!(owned.algorithm(i), Some(batch::Algorithm::$algorithm));
                                }
                            }
                        }
                        for buffer in &output {
                            assert_eq!(&buffer[..$width], &[0; $width]);
                            assert_eq!(buffer[$width], 0xa5);
                        }
                    }
                    // Public destinations have the opposite failure contract.
                    let mut output = [[0xa5; $width]; batch::CAPACITY];
                    let mut cancelled = || false;
                    assert!(executor.digest_public(&inputs,
                        output.each_mut().map(|b| Some(b.as_mut_slice())), &mut workspace,
                        &mut batch::Control::new(1024, &mut cancelled),
                        batch::PublicDeclassification::acknowledge()).is_err());
                    assert!(output.iter().flatten().all(|&b| b == 0xa5));
                }
            }
        };
    }
    ordinary!(ordinary256, batch, sha256_batch, Sha256, sha256);
    ordinary!(ordinary512, batch512, sha512_batch, Sha512, sha512);
    secret!(secret256, hardened_batch, sha256_hardened_batch, Sha256, sha256, 32);
    secret!(secret512, hardened_batch512, sha512_hardened_batch, Sha512, sha512, 64);
}
'''
