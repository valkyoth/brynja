"""Heterogeneous lane identities, compaction and general-t SIMD public fixtures."""

SOURCE = r'''
use brynja_strict::{batch::*,sha2::Sha512TBits};
#[derive(Clone)] struct Case {a:Algorithm,n:usize,x:Vec<u8>,out:Vec<u8>}
fn hex(s:&str)->Vec<u8> {s.as_bytes().chunks_exact(2).map(|p|u8::from_str_radix(core::str::from_utf8(p).unwrap(),16).unwrap()).collect()}
fn route(a:Algorithm,native:bool)->Route {
    #[cfg(target_arch="x86_64")] let k=(Sha256Kernel::Avx2,Sha512Kernel::Avx2,KeccakKernel::Avx2);
    #[cfg(target_arch="aarch64")] let k=(Sha256Kernel::Neon,Sha512Kernel::Neon,KeccakKernel::Neon);
    match a {Algorithm::Sha256(_)=>Route::Sha256(native.then_some(k.0)),Algorithm::Sha512(_)=>Route::Sha512(native.then_some(k.1)),
        Algorithm::Keccak(_,_)=>Route::Keccak(native.then_some(k.2))}
}
pub fn run() {
    let mut pools:[Vec<Case>;3]=std::array::from_fn(|_|vec![]);
    for line in include_str!("hashes.txt").lines() {
        let c:Vec<_>=line.split_whitespace().collect();
        if c[1].len()!=4097*2 {continue;}
        let out=hex(c[2]);
        let (group,a)=match c[0] {
            "sha224"=>(0,Algorithm::Sha256(Sha256Algorithm::Sha224)),"sha256"=>(0,Algorithm::Sha256(Sha256Algorithm::Sha256)),
            "sha384"=>(1,Algorithm::Sha512(Sha512Algorithm::Sha384)),"sha512"=>(1,Algorithm::Sha512(Sha512Algorithm::Sha512)),
            "sha512_224"=>(1,Algorithm::Sha512(Sha512Algorithm::Sha512_224)),"sha512_256"=>(1,Algorithm::Sha512(Sha512Algorithm::Sha512_256)),
            s=>(2,Algorithm::Keccak(match s {"sha3_224"=>KeccakAlgorithm::Sha3_224,"sha3_256"=>KeccakAlgorithm::Sha3_256,
                "sha3_384"=>KeccakAlgorithm::Sha3_384,"sha3_512"=>KeccakAlgorithm::Sha3_512,"shake_128"=>KeccakAlgorithm::Shake128,
                "shake_256"=>KeccakAlgorithm::Shake256,_=>panic!("identity")},out.len()*8)),
        };
        pools[group].push(Case{a,n:4097*8,x:hex(c[1]),out});
    }
    for line in include_str!("vectors/general-sha512-t-digest.txt").lines() {
        let c:Vec<_>=line.split_whitespace().collect();
        let t:u16=c[0].parse().unwrap(); let n=c[1].parse().unwrap();
        if n==2055 {pools[1].push(Case{a:Algorithm::Sha512(Sha512Algorithm::Sha512T(Sha512TBits::new(t).unwrap())),n,x:hex(c[2]),out:hex(c[3])});}
    }
    assert_eq!(pools.each_ref().map(|p|p.len()),[2,514,6]);
    let (mut scalar,mut vector,mut lanes)=(0,0,0);
    for (group,pool) in pools.iter().enumerate() {
        let capacity=if group==0 {8} else {4};
        for offset in 0..pool.len() {
            for native in [false,true].into_iter().filter(|n|!n||cfg!(feature="native")) {
                // Mixed identities and lengths; all slots are active for SIMD eligibility.
                let selected:Vec<_>=(0..capacity).map(|i|&pool[(offset+i/2)%pool.len()]).collect();
                let a=selected[0].a;
                let mut s=Session::new(route(a,native),Limits{stack_bytes:262144,max_stack_mapping_bytes:1048576,
                    max_buffer_mapping_bytes:1048576,max_input_bytes:65536,max_customization_bytes:0,max_output_bytes:32768}).unwrap();
                let raw=std::array::from_fn(|i|selected.get(i).map(|c|Input{algorithm:c.a,message:Bits{bytes:&c.x,
                    valid_bits:((c.n-1)%8+1) as u8},name:Bits::bytes(b""),customization:Bits::bytes(b"")}));
                match s.digest(&raw,100000,&Cancellation::new()) {
                    Ok(output)=>{
                        for (i,c) in selected.iter().enumerate() {assert_eq!(output.algorithm(i),Some(c.a));assert_eq!(output.expose(i),Some(c.out.as_slice()));lanes+=1;}
                        let calls=match output.report(){Report::Sha256(r)=>r.vector_calls,Report::Sha512(r)=>r.vector_calls,Report::Keccak(r)=>r.vector_calls};
                        assert_eq!(calls>0,native); if native {vector+=1;} else {scalar+=1;}
                    },
                    Err(e)=>panic!("mixed group {group} offset {offset} native={native}: {e:?}"),
                };
            }
        }
    }
    assert_eq!((scalar,vector,lanes),if cfg!(feature="native") {(522,522,4192)} else {(522,0,2096)});
    println!("\nSTRICT_GROUP_MIXED: scalar={scalar}; SIMD={vector}; lanes={lanes}; general-t=510");
}
'''
