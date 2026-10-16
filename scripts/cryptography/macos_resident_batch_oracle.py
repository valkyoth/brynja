"""Independent batch vectors from hashlib and the cross-checked Python sponge."""
import macos_resident_oracle


def write_consumer(consumer):
    count = macos_resident_oracle.write_consumer(consumer)
    if count != 662:
        raise ValueError('batch oracle population changed')
    (consumer / 'src/main.rs').write_text(SOURCE)
    return count


SOURCE = r'''
use brynja_crypto_cpu_std::macos_resident::batch::*;
fn hex(s: &str) -> Vec<u8> {
    if s=="-" { return Vec::new(); }
    s.as_bytes().chunks_exact(2).map(|p|
        u8::from_str_radix(core::str::from_utf8(p).unwrap(),16).unwrap()).collect()
}
fn bits(bytes: &[u8], n: usize) -> Bits<'_> {
    Bits { bytes, valid_bits: if n==0 {0} else {((n-1)%8+1) as u8} }
}
fn limits() -> Limits { Limits {stack_bytes:262144,max_stack_mapping_bytes:1048576,
    max_buffer_mapping_bytes:1048576,max_input_bytes:100000,max_customization_bytes:100000,
    max_output_bytes:65536} }
fn route(a: Algorithm, simd: bool) -> Route {
    match a {
        Algorithm::Sha256(_)=>Route::Sha256(simd.then_some(Sha256Kernel::Neon)),
        Algorithm::Sha512(_)=>Route::Sha512(simd.then_some(Sha512Kernel::Neon)),
        Algorithm::Keccak(_,_)=>Route::Keccak(simd.then_some(KeccakKernel::Neon)),
    }
}
fn execute(raw: &Input<'_>, expected: &[u8], simd: bool) -> Result<bool,Box<dyn std::error::Error>> {
    let r=route(raw.algorithm,simd);
    let mut session=Session::new(r,limits())?;
    let capacity=if matches!(r,Route::Sha256(_)) {8} else {4};
    let inputs=core::array::from_fn(|i| (i<capacity).then(|| Input {
        algorithm:raw.algorithm,
        message:Bits{bytes:raw.message.bytes,valid_bits:raw.message.valid_bits},
        name:Bits{bytes:raw.name.bytes,valid_bits:raw.name.valid_bits},
        customization:Bits{bytes:raw.customization.bytes,valid_bits:raw.customization.valid_bits},
    }));
    let output=session.digest(&inputs,100000,&Cancellation::new());
    match output {
        Err(Error::Sha256(brynja_hash_sha2::hardened_batch::Error::IneligibleWorkload))
        | Err(Error::Sha512(brynja_hash_sha2::hardened_batch512::Error::IneligibleWorkload))
        | Err(Error::Keccak(brynja_hash_sha3::hardened_batch::Error::IneligibleWorkload)) => {
            assert!(simd && raw.message.bytes.len() <= 168);
            Ok(false)
        },
        other=>{
            let out=other?;
            for i in 0..capacity { assert_eq!(out.expose(i),Some(expected)); }
            assert!(out.expose(capacity).is_none());
            match out.report() {
                Report::Sha256(report)=>assert_eq!(report.kernel,simd.then_some(Sha256Kernel::Neon)),
                Report::Sha512(report)=>assert_eq!(report.kernel,simd.then_some(Sha512Kernel::Neon)),
                Report::Keccak(report)=>assert_eq!(report.kernel,simd.then_some(KeccakKernel::Neon)),
            }
            Ok(true)
        }
    }
}
fn main() -> Result<(),Box<dyn std::error::Error>> {
    let (mut scalar,mut vector,mut rejected)=(0,0,0);
    for line in include_str!("hashes.txt").lines() {
        let c:Vec<_>=line.split_whitespace().collect(); assert_eq!(c.len(),3);
        let (x,out)=(hex(c[1]),hex(c[2]));
        let a=match c[0] {
            "sha224"=>Algorithm::Sha256(Sha256Algorithm::Sha224),
            "sha256"=>Algorithm::Sha256(Sha256Algorithm::Sha256),
            "sha384"=>Algorithm::Sha512(Sha512Algorithm::Sha384),
            "sha512"=>Algorithm::Sha512(Sha512Algorithm::Sha512),
            "sha512_224"=>Algorithm::Sha512(Sha512Algorithm::Sha512_224),
            "sha512_256"=>Algorithm::Sha512(Sha512Algorithm::Sha512_256),
            name=>Algorithm::Keccak(match name {
                "sha3_224"=>KeccakAlgorithm::Sha3_224, "sha3_256"=>KeccakAlgorithm::Sha3_256,
                "sha3_384"=>KeccakAlgorithm::Sha3_384, "sha3_512"=>KeccakAlgorithm::Sha3_512,
                "shake_128"=>KeccakAlgorithm::Shake128,"shake_256"=>KeccakAlgorithm::Shake256,
                _=>panic!("unknown oracle identity")},out.len()*8),
        };
        let raw=Input::bytes(a,&x);
        assert!(execute(&raw,&out,false)?); scalar+=1;
        if execute(&raw,&out,true)? {vector+=1;} else {rejected+=1;}
    }
    for line in include_str!("cshake.txt").lines() {
        let c:Vec<_>=line.split_whitespace().collect(); assert_eq!(c.len(),9);
        let (n,s,x,out)=(hex(c[2]),hex(c[4]),hex(c[6]),hex(c[8]));
        let a=match c[0] {"cshake128"=>KeccakAlgorithm::Cshake128,
            "cshake256"=>KeccakAlgorithm::Cshake256,_=>panic!("unknown cSHAKE")};
        let raw=Input{algorithm:Algorithm::Keccak(a,c[7].parse()?),
            message:bits(&x,c[5].parse()?),name:bits(&n,c[1].parse()?),
            customization:bits(&s,c[3].parse()?)};
        assert!(execute(&raw,&out,false)?); scalar+=1;
        if execute(&raw,&out,true)? {vector+=1;} else {rejected+=1;}
    }
    assert_eq!((scalar,vector,rejected),(662,616,46));
    println!("RESIDENT_BATCH_ORACLE: scalar={scalar}; NEON={vector}; ineligible={rejected}");
    Ok(())
}
'''
