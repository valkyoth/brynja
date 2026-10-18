"""Public-only strict batch/ParallelHash consumers; independent shared corpora."""
import sys

import strict_public_consumer as scalar
import strict_accelerated_sources as accelerated
import strict_group_mixed

sys.path.insert(0, str(scalar.shared.ROOT / 'scripts/cryptography'))
import macos_resident_batch_oracle as batch_oracle
import macos_resident_parallel_oracle as parallel_oracle

once = scalar.cases.replace_once


def batch_source():
    text = once(batch_oracle.SOURCE, 'use brynja_crypto_cpu_std::macos_resident::batch::*;',
                'use brynja_strict::batch::*;')
    for family in ('Sha256', 'Sha512', 'Keccak'):
        text = text.replace(f'{family}Kernel::Neon', f'{family.lower()}_kernel()')
    start = text.index('        Err(Error::Sha256(')
    end = text.index(' => {', start)
    text = text[:start] + '''        Err(e) if matches!(format!("{e:?}").as_str(),
            "Sha256(IneligibleWorkload)" | "Sha512(IneligibleWorkload)" | "Keccak(IneligibleWorkload)")''' + text[end:]
    text = text.replace('if execute(&raw,&out,true)?', 'if cfg!(feature="native") && execute(&raw,&out,true)?')
    # Generic runs do not count a route which was never requested as rejected.
    text = text.replace('else {rejected+=1;}', 'else if cfg!(feature="native") {rejected+=1;}')
    text = once(text, 'assert_eq!((scalar,vector,rejected),(662,616,46));',
                'assert_eq!((scalar,vector,rejected),if cfg!(feature="native") {(662,616,46)} else {(662,0,0)});')
    text = once(text, 'RESIDENT_BATCH_ORACLE: scalar={scalar}; NEON={vector}; ineligible={rejected}',
                r'\nSTRICT_GROUP_BATCH: scalar={scalar}; SIMD={vector}; ineligible={rejected}')
    text = once(text, 'fn main()', 'pub fn run()')
    for family in ('Sha256', 'Sha512', 'Keccak'):
        text += f'''
fn {family.lower()}_kernel()->{family}Kernel {{
    #[cfg(target_arch="x86_64")] {{ {family}Kernel::Avx2 }}
    #[cfg(target_arch="aarch64")] {{ {family}Kernel::Neon }}
}}
'''
    # Public reports must show actual vector work, not only the requested route.
    text = once(text, '            match out.report() {', '''            let calls=match out.report() {
                Report::Sha256(r)=>r.vector_calls, Report::Sha512(r)=>r.vector_calls,
                Report::Keccak(r)=>r.vector_calls,
            };
            assert_eq!(calls>0,simd);
            match out.report() {''')
    return text


def parallel_source():
    text = once(parallel_oracle.SOURCE,
                'use brynja_hash_parallel_std::{CancellationToken, macos_resident::*};',
                'use brynja_strict::parallelhash::*;')
    text = text.replace('CancellationToken::new()', 'Default::default()')
    text = text.replace('Kernel::ArmKeccak', 'root_kernel()').replace('BatchKernel::Neon', 'batch_kernel()')
    text = once(text, '            for (route,index) in', '            if cfg!(feature="native") { for (route,index) in')
    text = once(text, 'counts[index]+=1;\n            }', 'counts[index]+=1;\n            }}')
    text = once(text, 'assert_eq!(counts,[548;3]);',
                'assert_eq!(counts,if cfg!(feature="native") {[548;3]} else {[548,0,0]});')
    text = once(text, 'println!("RESIDENT_PARALLELHASH_ORACLE: scalar=548; Arm=548; NEON=548; workers=1,3");',
                r'println!("\nSTRICT_GROUP_PARALLEL: scalar={}; single={}; SIMD={}; workers=1,3",counts[0],counts[1],counts[2]);')
    return once(text, 'fn main()', 'pub fn run()') + PARALLEL_KERNELS


PARALLEL_KERNELS = r'''
fn root_kernel()->Kernel {
    #[cfg(target_arch="x86_64")] { Kernel::X86Keccak }
    #[cfg(target_arch="aarch64")] { Kernel::ArmKeccak }
}
fn batch_kernel()->BatchKernel {
    #[cfg(target_arch="x86_64")] { BatchKernel::Avx2 }
    #[cfg(target_arch="aarch64")] { BatchKernel::Neon }
}
'''


def install(consumer, roots):
    scalar.install(consumer, roots)
    manifest = consumer / 'Cargo.toml'
    text = once(manifest.read_text(), 'default-features=false}', 'default-features=false,features=["acceleration"]}')
    manifest.write_text(text + '\n[features]\nnative=[]\n')
    if parallel_oracle.write_consumer(consumer) != 274:
        raise ValueError('strict ParallelHash corpus changed')
    (consumer / 'src/main.rs').unlink()  # The oracle writer creates this known temporary file.
    (consumer / 'src/batch.rs').write_text(batch_source())
    (consumer / 'src/parallel.rs').write_text(parallel_source())
    (consumer / 'src/bin').mkdir()
    (consumer / 'src/bin/cpu.rs').write_text(accelerated.PROBE)
    (consumer / 'tests/acceptance.rs').write_text('''#![forbid(unsafe_code)]
#[path="../src/batch.rs"] mod batch;
#[path="../src/parallel.rs"] mod parallel;
#[path="../src/group_bits.rs"] mod group_bits;
#[path="../src/group_mixed.rs"] mod group_mixed;
#[test] fn batch_oracles(){batch::run().unwrap();}
#[test] fn parallel_oracles(){parallel::run().unwrap();}
#[test] fn batch_bits(){group_bits::run();}
#[test] fn mixed_lanes(){group_mixed::run();}
''' + LIFECYCLE)
    (consumer / 'src/group_bits.rs').write_text(BITS)
    (consumer / 'src/group_mixed.rs').write_text(strict_group_mixed.SOURCE)


LIFECYCLE = r'''
use brynja_strict::{batch as b,parallelhash as p};
fn bl()->b::Limits { b::Limits {stack_bytes:262144,max_stack_mapping_bytes:1048576,
    max_buffer_mapping_bytes:1048576,max_input_bytes:65536,max_customization_bytes:4096,max_output_bytes:32768} }
fn pl()->p::Limits { p::Limits {workers:3,max_leaves:128,max_block_bytes:4096,max_customization_bytes:1024,
    max_output_bits:65536,stack_bytes:262144,max_stack_mapping_bytes:1048576,max_buffer_mapping_bytes:1048576} }
fn bk()->b::Sha256Kernel {
    #[cfg(target_arch="x86_64")] {b::Sha256Kernel::Avx2}
    #[cfg(target_arch="aarch64")] {b::Sha256Kernel::Neon}
}
fn pk()->p::Kernel {
    #[cfg(target_arch="x86_64")] {p::Kernel::X86Keccak}
    #[cfg(target_arch="aarch64")] {p::Kernel::ArmKeccak}
}
#[test] fn batch_lifecycle() {
    for native in [false,true].into_iter().filter(|n| !n || cfg!(feature="native")) {
        let route=b::Route::Sha256(native.then_some(bk()));
        let mut s=b::Session::new(route,bl()).unwrap(); assert_eq!(s.route(),route);
        let data=[42;1024]; let a=b::Algorithm::Sha256(b::Sha256Algorithm::Sha256);
        let inputs=std::array::from_fn(|i| if !native&&(i==0||i==7) {None} else {Some(b::Input::bytes(a,&data))});
        let cancel=b::Cancellation::new(); cancel.cancel();
        assert!(matches!(s.digest(&inputs,10000,&cancel),Err(b::Error::Cancelled)));
        assert!(s.digest(&inputs,0,&b::Cancellation::new()).is_err()); assert!(!s.is_quarantined());
        let mut wrong=std::array::from_fn(|_| None); wrong[0]=Some(b::Input{algorithm:a,
            message:b::Bits{bytes:&[0xff],valid_bits:1},name:b::Bits::bytes(b""),customization:b::Bits::bytes(b"")});
        assert!(matches!(s.digest(&wrong,10000,&b::Cancellation::new()),Err(b::Error::InvalidInput)));
        assert!(!s.is_quarantined());
        let loan=s.digest(&inputs,10000,&b::Cancellation::new()).unwrap();
        assert!(loan.expose(8).is_none());
        if !native {assert!(loan.expose(0).is_none()&&loan.expose(7).is_none());}
        for i in 1..7 {assert_eq!(loan.algorithm(i),Some(a));}
        let expected=loan.expose(1).unwrap().to_vec();
        let mut first=[0xa5;32]; let mut bad=[0x5a;31];
        assert_eq!(loan.declassify([None,Some(&mut first),Some(&mut bad),None,None,None,None,None],
            b::PublicDeclassification::acknowledge()),Err(b::Error::InvalidInput));
        assert_eq!(first,[0xa5;32]); assert_eq!(bad,[0x5a;31]);
        let loan=s.digest(&inputs,10000,&b::Cancellation::new()).unwrap();
        let mut public=[[0xa5;32];8];
        let slots:Vec<_>=public.iter_mut().map(|x|&mut x[..]).collect();
        let mut slots=slots.into_iter(); let out=std::array::from_fn(|i| {let v=slots.next().unwrap(); if !native&&(i==0||i==7) {None} else {Some(v)}});
        loan.declassify(out,b::PublicDeclassification::acknowledge()).unwrap();
        for x in &public[1..7] {assert_eq!(&x[..],expected);}
        core::mem::forget(s.digest(&inputs,10000,&b::Cancellation::new()).unwrap());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _out=s.digest(&inputs,10000,&b::Cancellation::new()).unwrap(); panic!("caller");
        })).is_err());
        assert_eq!(s.digest(&inputs,10000,&b::Cancellation::new()).unwrap().expose(1).unwrap(),expected);
        s.quarantine(); assert!(s.is_quarantined());
        assert!(matches!(s.digest(&inputs,10000,&b::Cancellation::new()),Err(b::Error::Quarantined)));
    }
}
#[test] fn parallel_lifecycle() {
    macro_rules! check {($s:expr) => {{
        let mut s=$s; let data=[42;2049];
        assert!(matches!(s.hash(&data,0,b""),Err(p::Error::WorkLimit)));
        assert!(matches!(s.compute(p::Bits{bytes:&[0xff],valid_bits:1},32,p::Bits::bytes(b""),&Default::default()),Err(p::Error::InvalidBits)));
        let cancel=Default::default();
        drop(s.compute(p::Bits::bytes(&data),32,p::Bits::bytes(b""),&cancel).unwrap());
        cancel.cancel();
        assert!(matches!(s.compute(p::Bits::bytes(&data),32,p::Bits::bytes(b""),&cancel),Err(p::Error::Cancelled)));
        let expected=s.hash(&data,32,b"custom").unwrap().expose().to_vec();
        let mut bad=[0xa5;32];
        assert_eq!(s.hash(&data,32,b"custom").unwrap().declassify(&mut bad,p::PublicDeclassification::acknowledge()),Err(p::Error::OutputLength));
        assert_eq!(bad,[0xa5;32]);
        let mut public=[0xa5;33]; s.hash(&data,32,b"custom").unwrap().declassify(&mut public,p::PublicDeclassification::acknowledge()).unwrap();
        assert_eq!(&public[..],expected); assert_eq!(public[32]&0xfe,0);
        core::mem::forget(s.hash(&data,32,b"custom").unwrap());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {let _out=s.hash(&data,32,b"custom").unwrap();panic!("caller");})).is_err());
        assert_eq!(s.hash(&data,32,b"custom").unwrap().expose(),expected); s
    }};}
    for a in [p::Algorithm::ParallelHash128(257),p::Algorithm::ParallelHash256(257),
              p::Algorithm::ParallelHashXof128(257),p::Algorithm::ParallelHashXof256(257)] {
        check!(p::Session::new(a,pl()).unwrap());
        if cfg!(feature="native") {
            #[cfg(target_arch="x86_64")] let batch=p::BatchKernel::Avx2;
            #[cfg(target_arch="aarch64")] let batch=p::BatchKernel::Neon;
            for leaf in [p::LeafRoute::Single(pk()),p::LeafRoute::Batch(batch)] {
                let mut s=check!(p::CompiledSession::new(a,pk(),leaf,pl()).unwrap());
                assert!(!s.is_quarantined()); s.quarantine(); assert!(s.is_quarantined());
                assert!(matches!(s.hash(b"",32,b""),Err(p::Error::Quarantined)));
            }
        }
    }
}
'''


BITS = r'''
use brynja_strict::{batch::*,sha2::Sha512TBits};
fn hex(text:&str)->Vec<u8> {
    if text=="-" {return vec![];} assert_eq!(text.len()%2,0);
    text.as_bytes().chunks_exact(2).map(|p|u8::from_str_radix(core::str::from_utf8(p).unwrap(),16).unwrap()).collect()
}
fn check(a:Algorithm,n:usize,x:&[u8],expected:&[u8]) {
    let route=match a {Algorithm::Sha256(_)=>Route::Sha256(None),Algorithm::Sha512(_)=>Route::Sha512(None),_=>unreachable!()};
    let mut s=Session::new(route,Limits{stack_bytes:262144,max_stack_mapping_bytes:1048576,
        max_buffer_mapping_bytes:1048576,max_input_bytes:100000,max_customization_bytes:0,max_output_bytes:4096}).unwrap();
    let mut raw=std::array::from_fn(|_|None); raw[3]=Some(Input{algorithm:a,message:Bits{bytes:x,valid_bits:if n==0 {0} else {((n-1)%8+1) as u8}},
        name:Bits::bytes(b""),customization:Bits::bytes(b"")});
    let output=s.digest(&raw,10000,&Cancellation::new()).unwrap();
    assert_eq!(output.algorithm(3),Some(a)); assert_eq!(output.expose(3),Some(expected));
    for i in [0,1,2,4,5,6,7,8] {assert!(output.expose(i).is_none());}
}
pub fn run() {
    let mut named=0;
    for row in include_str!("vectors/nist-bit-selected.txt").lines().filter(|s|!s.is_empty()&&!s.starts_with('#')) {
        let c:Vec<_>=row.split('|').collect(); assert_eq!(c.len(),4);
        let a=match c[0] {"SHA224"=>Algorithm::Sha256(Sha256Algorithm::Sha224),"SHA256"=>Algorithm::Sha256(Sha256Algorithm::Sha256),
            "SHA384"=>Algorithm::Sha512(Sha512Algorithm::Sha384),"SHA512"=>Algorithm::Sha512(Sha512Algorithm::Sha512),
            "SHA512_224"=>Algorithm::Sha512(Sha512Algorithm::Sha512_224),"SHA512_256"=>Algorithm::Sha512(Sha512Algorithm::Sha512_256),_=>panic!("identity")};
        let n:usize=c[1].parse().unwrap(); let x=hex(c[2]); check(a,n,&x[..n.div_ceil(8)],&hex(c[3])); named+=1;
    }
    let mut general=0;
    for row in include_str!("vectors/general-sha512-t-digest.txt").lines() {
        let c:Vec<_>=row.split_whitespace().collect(); assert_eq!(c.len(),4);
        let a=Algorithm::Sha512(Sha512Algorithm::Sha512T(Sha512TBits::new(c[0].parse().unwrap()).unwrap()));
        check(a,c[1].parse().unwrap(),&hex(c[2]),&hex(c[3])); general+=1;
    }
    assert_eq!((named,general),(240,4590)); println!("\nSTRICT_GROUP_BITS: named=240; general-t=4590; sparse scalar slots");
}
'''
