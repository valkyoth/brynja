"""Test-only scoped SHA-2 consumers of the existing recorded corpora."""
from facade_sha2_execution_sources import once


def main(text):
    text = once(text, 'mod general;', 'mod acceptance;\nmod corpus;\nmod lifecycle;\nmod general;')
    before = '    let count = named::run(&narrow, &wide)?;'
    if text.count(before) != 1 or text.count('fn main()') != 1:
        raise ValueError('scoped SHA-2 main inventory')
    return '#![forbid(unsafe_code)]\n' + text.split(before)[0] + MAIN_TAIL


MAIN_TAIL = r'''
    let count = named::run(&narrow, &wide)?;
    let general = general::run(&wide)?;
    let narrow_route = narrow.execution()?.route();
    let wide_route = wide.execution()?.route();
    if mode == "static" || mode == "hosted" {
        ensure(matches!(narrow_route, api::Route::Static(_) | api::Route::Runtime(_)))?;
        if !narrow_only { ensure(matches!(wide_route, api::Route::Static(_) | api::Route::Runtime(_)))?; }
    }
    let revoked = lifecycle::run(mode, narrow_only)?;
    println!("SHA-2 scoped execution acceptance: PASS; named={count}; general={general}; lifecycle=11; revocations={revoked}");
    println!("narrow={narrow_route:?}; wide={wide_route:?}");
    println!("consumer-observable output/reuse checks; no private-storage qualification; independently verified: NO; FIPS validated: NO");
    Ok(())
}

fn report(value: api::Report, route: api::Route, bits: usize, wide: bool, general: bool) -> Result<(), Box<dyn Error>> {
    let block = if wide { 1024 } else { 512 };
    let length = if wide { 128 } else { 64 };
    ensure(value.route == route && value.message_blocks == (bits / block) as u128 &&
           value.padding_blocks == if bits % block >= block - length { 2 } else { 1 })?;
    ensure(value.portable_iv_blocks == u128::from(general))
}
'''


def named(text):
    if text.count('fn hex(') != 1 or text.count('macro_rules! check_named') != 1 or text.count('pub(super) fn run(') != 1:
        raise ValueError('scoped SHA-2 named inventory')
    parser = text[text.index('fn hex('):text.index('macro_rules! check_named')]
    visitor = text[text.index('pub(super) fn run('):]
    for name in ('Sha224', 'Sha256', 'Sha384', 'Sha512', 'Sha512_224', 'Sha512_256'):
        visitor = once(visitor, f'check_named!({name},', f'check_named!({name}Workspace,')
    visitor = once(visitor, '../../../crates/brynja-hash-sha2/tests/vectors/nist-bit-selected.txt', 'vectors/nist-bit-selected.txt')
    return NAMED + parser + visitor


NAMED = r'''
use super::{Owner, checked, declassify, ensure, report};
use brynja_hash_sha2::{BitString, hardened_execution::in_place as api};
macro_rules! check_named {
    ($name:ident, $owner:expr, $bytes:expr, $bits:expr, $expected:expr, $block:expr) => {{
        let mut workspace = checked(api::$name::new($owner.execution()?))?;
        let route = workspace.route();
        ensure(route == $owner.execution()?.route())?;
        let width = if $bits == 0 { 0 } else { (($bits-1)%8+1) as u8 };
        let input = checked(BitString::new($bytes, width))?;
        let mut out = vec![0xa5; $expected.len()];
        let result = checked(checked(workspace.with(|state| state.finalize_bits_secret(input, &mut out)))?)?;
        ensure(result.digest.expose() == $expected)?;
        report(result.report, route, $bits, $block == 1024, false)?;
        drop(result); ensure(out.iter().all(|b| *b == 0))?;
        let result = checked(checked(workspace.with(|state| state.finalize_bits_public(input, &mut out, declassify())))?)?;
        ensure(out == $expected)?; report(result, route, $bits, $block == 1024, false)?;
        for stride in [1,19,128] {
            let result = checked(workspace.with(|mut state| -> Result<_, Box<dyn std::error::Error>> {
                for chunk in $bytes[..$bits/8].chunks(stride) { checked(state.update(&[]))?; checked(state.update(chunk))?; }
                let tail = checked(BitString::new(&$bytes[$bits/8..], ($bits%8) as u8))?;
                checked(state.finalize_bits_secret(tail, &mut out))
            }))??;
            ensure(result.digest.expose() == $expected)?;
            report(result.report, route, $bits, $block == 1024, false)?;
            drop(result); ensure(out.iter().all(|b| *b == 0))?;
        }
        if $bits%8 == 0 {
            let result = checked(workspace.with(|mut state| -> Result<_, Box<dyn std::error::Error>> {
                checked(state.update($bytes))?; checked(state.finalize_secret(&mut out))
            }))??;
            ensure(result.digest.expose() == $expected)?; drop(result);
            ensure(out.iter().all(|b| *b == 0))?;
            let result = checked(workspace.with(|mut state| -> Result<_, Box<dyn std::error::Error>> {
                checked(state.update($bytes))?; checked(state.finalize_public(&mut out, declassify()))
            }))??;
            ensure(out == $expected)?; report(result, route, $bits, $block == 1024, false)?;
        }
    }};
}
'''

GENERAL = r'''
use super::{Owner, checked, declassify, ensure, report};
use brynja_hash_sha2::{BitString, Sha512TBits, hardened_execution::in_place::Sha512TWorkspace};

pub(super) fn run(owner: &Owner) -> Result<usize, Box<dyn std::error::Error>> {
    let corpus = include_str!("vectors/general-sha512-t-digest.txt");
    let result = crate::corpus::visit(corpus, |t,bits,bytes,expected| {
        let case = || -> Result<(), Box<dyn std::error::Error>> {
            let p = checked(Sha512TBits::new(t))?;
            let mut workspace = checked(Sha512TWorkspace::new(p, owner.execution()?))?;
            ensure(workspace.parameter() == p)?;
            let route = workspace.route(); ensure(route == owner.execution()?.route())?;
            let width = if bits == 0 { 0 } else { ((bits-1)%8+1) as u8 };
            let input = checked(BitString::new(bytes,width))?;
            let value = checked(checked(workspace.with(|state| {
                assert_eq!(state.parameter(),p);
                state.finalize_bits_public(input,declassify())
            }))?)?;
            ensure(value.digest.parameter() == p && value.digest.as_bytes() == expected)?;
            report(value.report,route,bits,true,true)?;
            let mut output = vec![0xa5;p.output_bytes()];
            let value = checked(checked(workspace.with(|state| state.finalize_bits_secret(input,&mut output)))?)?;
            ensure(value.digest.parameter() == p && value.digest.as_bytes() == expected)?;
            report(value.report,route,bits,true,true)?;
            drop(value); ensure(output.iter().all(|b| *b == 0))?;
            for stride in [1,19,128] {
                let value = checked(workspace.with(|mut state| -> Result<_, Box<dyn std::error::Error>> {
                    for part in bytes[..bits/8].chunks(stride) { checked(state.update(&[]))?; checked(state.update(part))?; }
                    let tail = checked(BitString::new(&bytes[bits/8..],(bits%8) as u8))?;
                    checked(state.finalize_bits_public(tail,declassify()))
                }))??;
                ensure(value.digest.parameter() == p && value.digest.as_bytes() == expected)?;
                report(value.report,route,bits,true,true)?;
            }
            if bits%8 == 0 {
                let value = checked(workspace.with(|mut state| -> Result<_, Box<dyn std::error::Error>> {
                    checked(state.update(bytes))?; checked(state.finalize_public(declassify()))
                }))??;
                ensure(value.digest.as_bytes() == expected)?; report(value.report,route,bits,true,true)?;
                let value = checked(workspace.with(|mut state| -> Result<_, Box<dyn std::error::Error>> {
                    checked(state.update(bytes))?; checked(state.finalize_secret(&mut output))
                }))??;
                ensure(value.digest.parameter() == p && value.digest.as_bytes() == expected)?;
                report(value.report,route,bits,true,true)?;
                drop(value); ensure(output.iter().all(|b| *b == 0))?;
            }
            Ok(())
        };
        case().map_err(|_| crate::acceptance::Error::Mismatch)
    });
    let count = checked(result)?; ensure(count == 4590)?; Ok(count)
}
'''
