"""Packaged KMAC/TupleHash checks against independent, NIST-cross-checked Python.

Only synthetic public test data. Production key/tag minimums remain enabled.
Both scalar and required Arm routes consume the same independently formed cases.
"""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(family):
    spec = importlib.util.spec_from_file_location('resident_' + family,
        ROOT / f'scripts/{family}/check-{family}-differential.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_oracle()
    return module


def write_consumer(consumer):
    k, t = load('kmac'), load('tuplehash')
    lines = []
    for name, rate, xof in (('kmac128', 168, False), ('kmac256', 136, False),
                           ('kmacxof128', 168, True), ('kmacxof256', 136, True)):
        for i in range(64):
            kb, cb = (256, 257, 511, 512)[i % 4], (0, 3, 8, 17)[i % 4]
            mb = (0, 1, 7, 8, 9, rate * 8 - 1, rate * 8, rate * 8 + 1)[i % 8]
            ob = (256, 257, rate * 8 + 3, 32777)[i % 4]
            if xof and i % 7 == 0:
                ob = 0
            key, custom, message = (k.oracle.canonical(seed + i, n) for seed, n in
                ((0x100000, kb), (0x200000, cb), (0x300000, mb)))
            expected = k.kmac(rate, k.oracle.byte_bits(key)[:kb],
                k.oracle.byte_bits(message)[:mb], k.oracle.byte_bits(custom)[:cb], ob, xof)
            lines.append(f'{name} {kb} {key.hex()} {cb} {custom.hex() or "-"} '
                         f'{mb} {message.hex() or "-"} {ob} {expected.hex() or "-"}')
    (consumer / 'src/kmac.txt').write_text('\n'.join(lines) + '\n')
    tuples = t.cases()
    rows = []
    for name, custom, cb, items, ob, expected in tuples:
        fields = [name, str(cb), custom.hex() or '-', str(ob), expected.hex() or '-']
        for value, bits in items:
            fields.extend((str(bits), value.hex() or '-'))
        rows.append(' '.join(fields))
    (consumer / 'src/tuplehash.txt').write_text('\n'.join(rows) + '\n')
    (consumer / 'src/keyed.rs').write_text(SOURCE)
    return len(lines) + len(rows)


SOURCE = r'''
use brynja_crypto_cpu_std::macos_resident::{kmac as k,tuplehash as t};
fn hex(s:&str)->Vec<u8> {
    if s=="-" {return vec![];}
    s.as_bytes().chunks_exact(2).map(|p|
        u8::from_str_radix(core::str::from_utf8(p).unwrap(),16).unwrap()).collect()
}
fn valid(n:usize)->u8 {if n==0 {0} else {((n-1)%8+1) as u8}}
fn klimits()->k::Limits {k::Limits{stack_bytes:262144,max_stack_mapping_bytes:1048576,
    max_buffer_mapping_bytes:65536,max_message_bits:100000,max_setup_bits:8192,
    max_output_bits:100000,max_chunks:16}}
fn tlimits()->t::Limits {t::Limits{stack_bytes:262144,max_stack_mapping_bytes:1048576,
    max_buffer_mapping_bytes:65536,max_input_bits:100000,max_customization_bits:8192,
    max_output_bits:100000,max_items:16,max_chunks:32}}
pub fn run()->Result<(),Box<dyn std::error::Error>> {
    let mut count=0;
    for c in include_str!("kmac.txt").lines().map(|l|l.split_whitespace().collect::<Vec<_>>()) {
        assert_eq!(c.len(),9);
        let (key,custom,msg,expected)=(hex(c[2]),hex(c[4]),hex(c[6]),hex(c[8]));
        let (kb,cb,mb,ob):(usize,usize,usize,usize)=(c[1].parse()?,c[3].parse()?,c[5].parse()?,c[7].parse()?);
        let a=match c[0] {"kmac128"=>k::Algorithm::Kmac128(ob),"kmac256"=>k::Algorithm::Kmac256(ob),
            "kmacxof128"=>k::Algorithm::KmacXof128(ob),"kmacxof256"=>k::Algorithm::KmacXof256(ob),_=>panic!("identity")};
        let request=||k::Request{key:k::Bits{bytes:&key,valid_bits:valid(kb)},
            customization:k::Bits{bytes:&custom,valid_bits:valid(cb)},chunks:&[],
            tail:k::Bits{bytes:&msg,valid_bits:valid(mb)}};
        let cancel=k::Cancellation::new();
        macro_rules! check {($s:expr)=>{{
            let mut s=$s;
            assert_eq!(s.compute(request(),&cancel)?.expose(),expected);
            if ob>=256 {
                assert!(s.verify(request(),k::Bits{bytes:&expected,valid_bits:valid(ob)},&cancel)?);
                let mut wrong=expected.clone(); wrong[0]^=1;
                assert!(!s.verify(request(),k::Bits{bytes:&wrong,valid_bits:valid(ob)},&cancel)?);
            }
            count+=1;
        }}}
        check!(k::Session::new(a,klimits())?);
        check!(k::CompiledSession::new(a,k::Kernel::ArmKeccak,klimits())?);
    }
    for c in include_str!("tuplehash.txt").lines().map(|l|l.split_whitespace().collect::<Vec<_>>()) {
        assert!(c.len()>=5 && (c.len()-5)%2==0);
        let (custom,expected)=(hex(c[2]),hex(c[4]));
        let (cb,ob):(usize,usize)=(c[1].parse()?,c[3].parse()?);
        let a=match c[0] {"tuple128"=>t::Algorithm::TupleHash128(ob),"tuple256"=>t::Algorithm::TupleHash256(ob),
            "tuplexof128"=>t::Algorithm::TupleHashXof128(ob),"tuplexof256"=>t::Algorithm::TupleHashXof256(ob),_=>panic!("identity")};
        let data:Vec<_>=c[5..].chunks_exact(2).map(|p|(p[0].parse::<usize>().unwrap(),hex(p[1]))).collect();
        let items:Vec<_>=data.iter().map(|(n,b)|t::Item{chunks:&[],tail:t::Bits{bytes:b,valid_bits:valid(*n)}}).collect();
        let custom=||t::Bits{bytes:&custom,valid_bits:valid(cb)};
        let cancel=t::Cancellation::new();
        let mut scalar=t::Session::new(a,tlimits())?;
        let mut arm=t::CompiledSession::new(a,t::Kernel::ArmKeccak,tlimits())?;
        assert_eq!(scalar.compute(&items,custom(),&cancel)?.expose(),expected); count+=1;
        assert_eq!(arm.compute(&items,custom(),&cancel)?.expose(),expected); count+=1;
    }
    assert_eq!(count,1024);
    println!("RESIDENT_KEYED_ORACLE: 1024 passed; 512 scalar; 512 ArmKeccak"); Ok(())
}
'''
