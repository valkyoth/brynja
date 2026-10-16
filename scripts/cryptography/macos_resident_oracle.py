"""Independent packaged scalar-family cases, using hashlib and the Python sponge."""
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def write_consumer(consumer, accelerated=False):
    lines = []
    for algorithm in ('sha224', 'sha256', 'sha384', 'sha512', 'sha512_224',
                      'sha512_256', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
                      'shake_128', 'shake_256'):
        for length in (0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 135, 136, 167, 168, 4097):
            message = bytes((i * 73 + length) % 256 for i in range(length))
            digest = hashlib.new(algorithm, message)
            expected = digest.digest(4097) if algorithm.startswith('shake') else digest.digest()
            lines.append(f'{algorithm} {message.hex() or "-"} {expected.hex()}')
    (consumer / 'src/hashes.txt').write_text('\n'.join(lines) + '\n')
    spec = importlib.util.spec_from_file_location('resident_cshake_oracle',
                ROOT / 'scripts/sha3/check-cshake-differential.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    official = (
        (168, 'cshake128', 256, 'c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5'),
        (136, 'cshake256', 512, 'd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c'),
    )
    cases = oracle.cases()
    for rate, algorithm, bits, expected in official:
        message, customization = bytes(range(4)), b'Email Signature'
        actual = oracle.cshake(rate, oracle.byte_bits(message), [], oracle.byte_bits(customization), bits)
        if actual.hex() != expected:
            raise ValueError('Python cSHAKE oracle disagrees with NIST sample')
        empty = oracle.cshake(rate, oracle.byte_bits(b'abc'), [], [], 512)
        if empty != hashlib.new('shake_128' if rate == 168 else 'shake_256', b'abc').digest(64):
            raise ValueError('Python cSHAKE empty-prefix oracle disagrees with hashlib')
        cases.append((algorithm, b'', 0, customization, 120, message, 32, bits, actual))
    (consumer / 'src/cshake.txt').write_text('\n'.join(
        f'{a} {nb} {n.hex() or "-"} {sb} {s.hex() or "-"} {xb} {x.hex() or "-"} {ob} {out.hex() or "-"}'
        for a, n, nb, s, sb, x, xb, ob, out in cases) + '\n')
    source = SOURCE
    if accelerated:
        source = source.replace('sha2::Session::new(a,limits2())',
            'sha2::CompiledSession::new(a,if matches!(a,sha2::Algorithm::Sha224|sha2::Algorithm::Sha256) {sha2::Kernel::ArmSha256} else {sha2::Kernel::ArmSha512},limits2())')
        source = source.replace('sha3::Session::new(a,limits3())',
            'sha3::CompiledSession::new(a,sha3::Kernel::ArmKeccak,limits3())')
    (consumer / 'src/families.rs').write_text(source)
    return len(lines) + len(cases)


SOURCE = r'''
use brynja_crypto_cpu_std::macos_resident::{sha2,sha3};
fn hex(s: &str) -> Vec<u8> {
    if s=="-" { return Vec::new(); }
    s.as_bytes().chunks_exact(2).map(|pair| {
        let text=core::str::from_utf8(pair).unwrap();
        u8::from_str_radix(text,16).unwrap()
    }).collect()
}
fn limits2() -> sha2::Limits { sha2::Limits { stack_bytes:262144,
    max_stack_mapping_bytes:1048576,max_output_mapping_bytes:65536,
    max_message_bits:100000,max_chunks:16 } }
fn limits3() -> sha3::Limits { sha3::Limits { stack_bytes:262144,
    max_stack_mapping_bytes:1048576,max_output_mapping_bytes:65536,
    max_message_bits:100000,max_customization_bits:8192,max_output_bits:100000,max_chunks:16 } }
fn bits(bytes: &[u8], n: usize) -> sha3::Bits<'_> {
    sha3::Bits { bytes, valid_bits: if n==0 {0} else {((n-1)%8+1) as u8} }
}
pub fn run() -> Result<(),Box<dyn std::error::Error>> {
    let mut count=0;
    for line in include_str!("hashes.txt").lines() {
        let columns:Vec<_>=line.split_whitespace().collect(); assert_eq!(columns.len(),3);
        let (name,input,expected)=(columns[0],hex(columns[1]),hex(columns[2]));
        let a=match name {
            "sha224"=>Some(sha2::Algorithm::Sha224), "sha256"=>Some(sha2::Algorithm::Sha256),
            "sha384"=>Some(sha2::Algorithm::Sha384), "sha512"=>Some(sha2::Algorithm::Sha512),
            "sha512_224"=>Some(sha2::Algorithm::Sha512_224), "sha512_256"=>Some(sha2::Algorithm::Sha512_256),
            _=>None };
        if let Some(a)=a {
            let mut s=sha2::Session::new(a,limits2())?;
            assert_eq!(s.hash(&input)?.expose(),expected);
        } else {
            let a=match name {
                "sha3_224"=>sha3::Algorithm::Sha3_224, "sha3_256"=>sha3::Algorithm::Sha3_256,
                "sha3_384"=>sha3::Algorithm::Sha3_384, "sha3_512"=>sha3::Algorithm::Sha3_512,
                "shake_128"=>sha3::Algorithm::Shake128(expected.len()*8),
                "shake_256"=>sha3::Algorithm::Shake256(expected.len()*8), _=>panic!("unknown oracle identity") };
            let mut s=sha3::Session::new(a,limits3())?;
            assert_eq!(s.hash(&input)?.expose(),expected);
        }
        count+=1;
    }
    for line in include_str!("cshake.txt").lines() {
        let c:Vec<_>=line.split_whitespace().collect(); assert_eq!(c.len(),9);
        let (n,s,x,out)=(hex(c[2]),hex(c[4]),hex(c[6]),hex(c[8]));
        let width:usize=c[7].parse()?;
        let a=match c[0] { "cshake128"=>sha3::Algorithm::Cshake128(width),
            "cshake256"=>sha3::Algorithm::Cshake256(width), _=>panic!("unknown cSHAKE") };
        let mut session=sha3::Session::new(a,limits3())?;
        assert_eq!(session.hash_customized_chunks(&[],bits(&x,c[5].parse()?),
            bits(&n,c[1].parse()?),bits(&s,c[3].parse()?),&sha3::Cancellation::new())?.expose(),out);
        count+=1;
    }
    assert_eq!(count,662);
    println!("RESIDENT_FAMILY_ORACLE: {count} passed"); Ok(())
}
'''
