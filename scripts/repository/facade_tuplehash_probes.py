"""Public-only capability probe and compiled TupleHash ownership negatives."""
import json

PROBE = r'''
#![forbid(unsafe_code)]
use brynja_crypto_cpu::static_execution as raw;
use brynja_crypto_cpu_std::execution as hosted;
fn main() {
    let mut cpu = "none";
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx2") { cpu = "avx2"; }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon") &&
       std::arch::is_aarch64_feature_detected!("sha2") &&
       std::arch::is_aarch64_feature_detected!("sha3") { cpu = "arm-keccak"; }
    let kernel = if cfg!(target_arch = "x86_64") { raw::Kernel::X86Keccak }
                 else { raw::Kernel::ArmKeccak };
    println!("CPU:{cpu}");
    println!("KERNEL:{kernel:?}");
    match raw::Authority::new(kernel) {
        Ok(owner) => { assert_eq!(owner.report().health, raw::Health::Healthy); println!("STATIC:ready"); }
        Err(error @ (raw::Error::WrongArchitecture | raw::Error::MissingTargetFeatures)) => println!("STATIC:{error:?}"),
        Err(error) => panic!("static integrity failure: {error:?}"),
    }
    match hosted::Authority::new(kernel, hosted::Mode::Require) {
        Ok(owner) => {
            assert_eq!(owner.report().route, hosted::Route::Accelerated);
            assert_eq!(owner.report().health, Some(raw::Health::Healthy));
            assert!(owner.session().unwrap().is_some());
            println!("HOSTED:ready");
        }
        Err(hosted::Error::Unavailable(reason)) => println!("HOSTED:{reason:?}"),
        Err(error) => panic!("hosted integrity failure: {error:?}"),
    }
}
'''

OWNERS = (
    'TupleHash128', 'TupleHash256', 'TupleHashXof128', 'TupleHashXof256',
    'HardenedTupleHash128', 'HardenedTupleHash256', 'HardenedTupleHashXof128',
    'HardenedTupleHashXof256', 'Reader', 'HardenedReader', 'TupleItemWriter', 'KeccakSession',
)
SCOPED = tuple(f'in_place::{name}{width}{suffix}'
               for width in (128, 256)
               for name, suffixes in (('TupleHash', ('', 'Workspace', 'ItemWriter')),
                                      ('TupleHashXof', ('', 'Workspace', 'Reader')))
               for suffix in suffixes)
MISUSE = (
    ('fn writer(h:&mut t::TupleHash128) { if let Ok(mut w)=h.begin_item(8) { let _=h.push_item(&[]); let _=w.update(&[]); } }', 'E0499'),
    ('fn reuse(h:t::TupleHash128) { let _=h.finalize(&mut [0;32]); let _=h.report(); }', 'E0382'),
    ('fn reuse(h:t::HardenedTupleHash256) { let _=h.finalize_secret(&mut [0;32]); let _=h.report(); }', 'E0382'),
    ('fn borrow(h:&mut t::HardenedTupleHashXof128) { if let Ok(mut r)=h.finalize_xof() { let _=h.push_item(&[]); let _=r.squeeze_secret(&mut []); } }', 'E0499'),
    ('fn public(s:t::in_place::TupleHash128) { let _=s.finalize_public(&mut []); }', 'E0061'),
    ('fn public(mut r:t::in_place::TupleHashXof256Reader) { let _=r.squeeze_public(&mut []); }', 'E0061'),
    ('fn ordinary<T:t::HardenedState>() {} pub fn probe() { ordinary::<t::TupleHash128>(); }', 'E0277'),
    ('fn convert(x:api::tuplehash::TupleHashSecretOutput) { let _: &[u8]=x; }', 'E0308'),
)


def diagnostic(result, code):
    messages = [json.loads(line) for line in result.stdout.splitlines()]
    return result.returncode == 101 and any(
        item.get('reason') == 'compiler-message' and item['message'].get('level') == 'error'
        and (item['message'].get('code') or {}).get('code') == code for item in messages)


def negatives(api, consumer, package, cargo, env):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    count = 0
    try:
        for owner in OWNERS + SCOPED:
            typename = 'api::tuplehash::execution::' + owner
            api.source(consumer, package, f'pub fn present(_: Option<{typename}>) {{}}\n')
            api.run(cargo + ['check', '--offline', '--lib'], consumer, env)
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                api.source(consumer, package, f'fn require<T:{bound}>() {{}}\n'
                           f'pub fn probe() {{ require::<{typename}>(); }}\n')
                result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'],
                                 consumer, env, success=False)
                api.require(diagnostic(result, 'E0277'), 'TupleHash trait rejection diagnostic: ' + owner)
                count += 1
        for body, code in MISUSE:
            api.source(consumer, package, 'use api::tuplehash::execution as t;\n' + body)
            result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'],
                             consumer, env, success=False)
            api.require(diagnostic(result, code), 'TupleHash misuse diagnostic: ' + code)
            count += 1
    finally:
        path.write_text(original)
    api.require(count == 128, 'TupleHash ownership population')
    print(f'PASS: {package}: 128 TupleHash trait/ownership/classification rejections', flush=True)
