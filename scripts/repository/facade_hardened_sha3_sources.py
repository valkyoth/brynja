"""Test-only public facade adapters; no alternate cryptographic implementation."""
from facade_sha2_execution_sources import once

COMMON = r'''
use brynja_crypto_cpu::static_execution as raw;
use brynja_crypto_cpu_std::execution as hosted;
use brynja_hash_sha3::{Fips202BitString, Fips202Output, hardened_execution as cpu};
fn error(value: impl core::fmt::Debug) -> String { format!("{value:?}") }
enum Authority { Static(raw::Authority), Hosted(hosted::Authority) }
fn kernel() -> raw::Kernel {
    if cfg!(target_arch="aarch64") { raw::Kernel::ArmKeccak } else { raw::Kernel::X86Keccak }
}
impl Authority {
    fn quarantine(&self) { match self { Self::Static(a) => a.quarantine(), Self::Hosted(a) => a.quarantine() } }
}
fn authority() -> Result<Option<Authority>, String> {
    match std::env::var("FACADE_SHA3_MODE").as_deref() {
        Ok("static") => raw::Authority::new(kernel()).map(Authority::Static).map(Some).map_err(error),
        Ok("hosted") => hosted::Authority::new(kernel(), hosted::Mode::Require).map(Authority::Hosted).map(Some).map_err(error),
        _ => Err("explicit required route missing".to_string()),
    }
}
fn session(owner: &Authority) -> Result<cpu::KeccakSession<'_>, String> {
    let s = match owner {
        Authority::Static(a) => cpu::KeccakSession::from_static(a).map_err(error)?,
        Authority::Hosted(a) => {
            assert_eq!(a.report().route, hosted::Route::Accelerated);
            cpu::KeccakSession::from_runtime(a.session().map_err(error)?.ok_or("missing required session")?).map_err(error)?
        }
    };
    assert_eq!(s.report().kernel, kernel());
    assert_eq!(s.report().health, raw::Health::Healthy);
    Ok(s)
}
#[test]
fn required_admission() -> Result<(), String> {
    let expected = std::env::var("FACADE_SHA3_EXPECT").map_err(error)?;
    match authority() {
        Ok(Some(a)) if expected == "ready" => { let _ = session(&a)?; }
        Err(e) if e == expected => {}
        _ => return Err("required admission changed".to_string()),
    }
    Ok(())
}
'''


def owned(text):
    text = once(text, '#![cfg(feature = "hardened-execution")]', '#![forbid(unsafe_code)]')
    start, end = text.index('use brynja_crypto_cpu::'), text.index('\n#[test]')
    if text.count('fn authority()') != 1 or text.count('#[test]') != 4:
        raise ValueError('hardened SHA-3 lifecycle inventory drift')
    return text[:start] + 'use brynja_hash_sha3 as portable;\n' + COMMON + text[end:]


CORPUS = r'''
fn bytes(s: &str, bits: usize) -> Vec<u8> {
    assert!(bits <= 32768);
    let mut value = if s == "-" { vec![] } else {
        assert!(s.len() <= 8192 && s.len() % 2 == 0 && s.is_ascii());
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect::<Vec<_>>()
    };
    // CAVP represents the zero-bit message by 00.
    if bits == 0 && value == [0] { value.clear(); }
    assert_eq!(value.len(), bits.div_ceil(8));
    if bits % 8 != 0 { assert_eq!(value.last().unwrap() >> (bits % 8), 0); }
    value
}
fn valid(bits: usize) -> u8 { if bits == 0 { 0 } else { ((bits-1)%8+1) as u8 } }
fn bit_string(value: &[u8], bits: usize) -> Fips202BitString<'_> { Fips202BitString::new(value, valid(bits)).unwrap() }
fn run_case(owner: &Authority, name: &str, n: &[u8], nb: usize, s: &[u8], sb: usize,
            input: &[u8], ib: usize, expected: &[u8], ob: usize) -> Result<(), String> {
    let prefix = ib / 8;
    let tail = bit_string(&input[prefix..], ib % 8);
    macro_rules! absorb { ($state:expr) => {{
        for chunk in input[..prefix].chunks(13) { $state.update(chunk).map_err(error)?; }
        $state.update(&[]).map_err(error)?;
    }}; }
    macro_rules! fixed { ($kind:ident, $workspace:ident) => {{
        for secret in [false, true] {
            let mut out = vec![0xa5; expected.len()];
            let mut state = cpu::$kind::new(session(owner)?).map_err(error)?;
            absorb!(state);
            if secret {
                let result = state.finalize_bits_secret(tail, &mut out).map_err(error)?;
                assert_eq!(result.expose(), expected); drop(result); assert!(out.iter().all(|x| *x==0));
            } else {
                state.finalize_bits_public(tail, &mut out, cpu::Sha3PublicDeclassification::acknowledge()).map_err(error)?;
                assert_eq!(out, expected);
            }
            let mut workspace = cpu::in_place::$workspace::new(session(owner)?).map_err(error)?;
            workspace.with(|mut state| -> Result<(), String> {
                absorb!(state); out.fill(0xa5);
                if secret {
                    let result = state.finalize_bits_secret(tail, &mut out).map_err(error)?;
                    assert_eq!(result.expose(), expected); drop(result); assert!(out.iter().all(|x| *x==0));
                } else {
                    state.finalize_bits_public(tail, &mut out, cpu::Sha3PublicDeclassification::acknowledge()).map_err(error)?;
                    assert_eq!(out, expected);
                }
                Ok(())
            }).map_err(error)??;
        }
    }}; }
    macro_rules! read { ($reader:expr, $secret:expr) => {{
        let mut reader = $reader;
        let mut out = vec![0xa5; expected.len()];
        // Cross a rate boundary when the fixture is long enough, retaining
        // the last partial byte for the consuming final-output operation.
        let first = (ob / 8).min(173);
        let mut scratch = vec![0x93; out.len()+7];
        if $secret {
            let result = reader.squeeze_secret(&mut out[..first]).map_err(error)?;
            assert_eq!(result.expose(), &expected[..first]); drop(result);
            let result = reader.squeeze_final_bits_secret(&mut out[first..], valid(ob-first*8)).map_err(error)?;
            assert_eq!(result.expose(), &expected[first..]); drop(result);
            assert!(out.iter().all(|x| *x==0));
        } else {
            reader.squeeze_public_with_scratch(&mut out[..first], &mut scratch, cpu::Sha3PublicDeclassification::acknowledge()).map_err(error)?;
            assert!(scratch.iter().all(|x| *x==0)); scratch.fill(0x93);
            reader.squeeze_final_bits_public(Fips202Output::new(&mut out[first..], valid(ob-first*8)).map_err(error)?,
                &mut scratch, cpu::Sha3PublicDeclassification::acknowledge()).map_err(error)?;
            assert_eq!(out, expected); assert!(scratch.iter().all(|x| *x==0));
        }
    }}; }
    macro_rules! xof { ($state:expr, $workspace:ident, $method:ident $(, $arg:expr)*) => {{
        for secret in [false, true] {
            let mut state = $state; absorb!(state);
            read!(state.finalize_bits_xof(tail).map_err(error)?, secret);
            let mut workspace = cpu::in_place::$workspace::new(session(owner)?).map_err(error)?;
            workspace.$method($($arg,)* |mut state| -> Result<(), String> {
                absorb!(state); read!(state.finalize_bits_xof(tail).map_err(error)?, secret); Ok(())
            }).map_err(error)??;
        }
    }}; }
    match name {
        "sha3-224" => fixed!(Sha3_224, Sha3_224Workspace),
        "sha3-256" => fixed!(Sha3_256, Sha3_256Workspace),
        "sha3-384" => fixed!(Sha3_384, Sha3_384Workspace),
        "sha3-512" => fixed!(Sha3_512, Sha3_512Workspace),
        "shake128" => xof!(cpu::Shake128::new(session(owner)?).map_err(error)?, Shake128Workspace, with),
        "shake256" => xof!(cpu::Shake256::new(session(owner)?).map_err(error)?, Shake256Workspace, with),
        "cshake128" => xof!(cpu::Cshake128::new_bits(session(owner)?, bit_string(n,nb), bit_string(s,sb)).map_err(error)?,
            Cshake128Workspace, with_bits, bit_string(n,nb), bit_string(s,sb)),
        "cshake256" => xof!(cpu::Cshake256::new_bits(session(owner)?, bit_string(n,nb), bit_string(s,sb)).map_err(error)?,
            Cshake256Workspace, with_bits, bit_string(n,nb), bit_string(s,sb)),
        _ => return Err("unknown corpus identity".to_string()),
    }
    Ok(())
}
#[test]
fn recorded_vectors_owned_and_scoped() -> Result<(), String> {
    let owner = authority()?.ok_or("missing required authority")?;
    let mut counts = [0; 8];
    for (custom, corpus) in [(false, include_str!("vectors/nist-bit-selected.txt")),
                             (true, include_str!("vectors/cshake-execution.txt"))] {
        let mut count = 0;
        for line in corpus.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let f = line.split_whitespace().collect::<Vec<_>>();
            assert_eq!(f.len(), if custom { 9 } else { 5 });
            let (nb,n,sb,s,ib,x,ob,y) = if custom { (f[1],f[2],f[3],f[4],f[5],f[6],f[7],f[8]) }
                                      else { ("0","-","0","-",f[1],f[3],f[2],f[4]) };
            let (nb,sb,ib,ob) = (nb.parse().unwrap(),sb.parse().unwrap(),ib.parse().unwrap(),ob.parse().unwrap());
            let index = ["sha3-224","sha3-256","sha3-384","sha3-512","shake128","shake256","cshake128","cshake256"]
                .iter().position(|name| *name==f[0]).ok_or("unknown identity")?;
            run_case(&owner,f[0],&bytes(n,nb),nb,&bytes(s,sb),sb,&bytes(x,ib),ib,&bytes(y,ob),ob)?;
            counts[index] += 1; count += 1;
        }
        assert_eq!(count, if custom { 628 } else { 76 });
    }
    assert!(counts.iter().all(|n| *n > 0));
    println!("HARDENED_SHA3_CORPUS: nist=76; cshake=628; owned/scoped; public/secret");
    Ok(())
}
'''
