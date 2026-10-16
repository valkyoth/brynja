"""Resident ParallelHash cases from the existing independent bit-oriented oracle."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('parallel_reference',
    ROOT / 'scripts/parallelhash/check-parallelhash-differential.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def vectors():
    cases = reference.cases()
    # Anchor the composed oracle to published NIST short-message examples.
    message = bytes.fromhex('000102030405060710111213141516172021222324252627')
    for rate, expected in (
        (168, 'ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5'),
        (136, 'bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c451105531b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429'),
    ):
        bits = len(expected) * 4
        actual = reference.parallel_hash(rate, reference.oracle.byte_bits(message), 8, [], bits, False)
        if actual.hex() != expected:
            raise ValueError('ParallelHash independent oracle disagrees with NIST')
        cases.append(('parallel128' if rate == 168 else 'parallel256', b'', 0, message, 192, 8, bits, actual))
    # Real multi-wave SIMD lengths, complete/tail groups, block/rate boundaries,
    # partial input/customization/output and multi-chunk XOF output.
    for algorithm, rate, xof in (('parallel128', 168, False), ('parallel256', 136, False),
                                 ('parallelxof128', 168, True), ('parallelxof256', 136, True)):
        for index, (length, block, output) in enumerate(((4097, 136, 257), (4096, 168, 32769),
                                                       (4097, 256, 0), (4352, 136, 512))):
            mbits = length * 8 - index
            message = reference.oracle.canonical(417 + index, mbits)
            custom = reference.oracle.canonical(271 + index, 17)
            expected = reference.parallel_hash(rate, reference.oracle.byte_bits(message)[:mbits], block,
                                               reference.oracle.byte_bits(custom)[:17], output, xof)
            cases.append((algorithm, custom, 17, message, mbits, block, output, expected))
    return cases


def write_consumer(consumer):
    cases = vectors()
    (consumer / 'src/vectors.txt').write_text('\n'.join(
        f'{a} {cb} {c.hex() or "-"} {mb} {m.hex() or "-"} {block} {ob} {expected.hex() or "-"}'
        for a, c, cb, m, mb, block, ob, expected in cases) + '\n')
    (consumer / 'src/main.rs').write_text(SOURCE)
    return len(cases)


SOURCE = r'''
use brynja_hash_parallel_std::{CancellationToken, macos_resident::*};
fn hex(s: &str) -> Vec<u8> {
    if s=="-" { return Vec::new(); }
    s.as_bytes().chunks_exact(2).map(|p|
        u8::from_str_radix(core::str::from_utf8(p).unwrap(),16).unwrap()).collect()
}
fn bits(bytes: &[u8], n: usize) -> Bits<'_> {
    Bits { bytes, valid_bits: if n==0 {0} else {((n-1)%8+1) as u8} }
}
fn limits(workers: usize) -> Limits {
    Limits {workers,max_leaves:128,max_block_bytes:4096,max_customization_bytes:1024,
        max_output_bits:65536,stack_bytes:262144,max_stack_mapping_bytes:1048576,
        max_buffer_mapping_bytes:1048576}
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts=[0;3];
    for workers in [1,3] {
        for line in include_str!("vectors.txt").lines() {
            let c:Vec<_>=line.split_whitespace().collect(); assert_eq!(c.len(),8);
            let (custom,message,expected)=(hex(c[2]),hex(c[4]),hex(c[7]));
            let (cb,mb,block,ob)=(c[1].parse()?,c[3].parse()?,c[5].parse()?,c[6].parse()?);
            let a=match c[0] {"parallel128"=>Algorithm::ParallelHash128(ob),
                "parallel256"=>Algorithm::ParallelHash256(ob),
                "parallelxof128"=>Algorithm::ParallelHashXof128(ob),
                "parallelxof256"=>Algorithm::ParallelHashXof256(ob),_=>panic!("identity")};
            let mut scalar=Session::new(a,limits(workers))?;
            let output=scalar.compute(bits(&message,mb),block,bits(&custom,cb),&CancellationToken::new())?;
            assert_eq!(output.expose(),expected); drop(output); counts[0]+=1;
            for (route,index) in [(LeafRoute::Single(Kernel::ArmKeccak),1), (LeafRoute::Batch(BatchKernel::Neon),2)] {
                let mut session=CompiledSession::new(a,Kernel::ArmKeccak,route,limits(workers))?;
                assert_eq!(session.routes(),(Kernel::ArmKeccak,route));
                let output=session.compute(bits(&message,mb),block,bits(&custom,cb),&CancellationToken::new())?;
                assert_eq!(output.expose(),expected); drop(output); counts[index]+=1;
            }
        }
    }
    assert_eq!(counts,[548;3]);
    println!("RESIDENT_PARALLELHASH_ORACLE: scalar=548; Arm=548; NEON=548; workers=1,3");
    Ok(())
}
'''
