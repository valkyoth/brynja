"""Strict-only public SHA-2 bit consumer for recorded NIST/general-t vectors."""

SOURCE = r'''
use brynja_strict::sha2::{self,Algorithm as A};
fn hex(text:&str)->Vec<u8> {
    if text=="-" {return vec![];}
    assert_eq!(text.len()%2,0);
    text.as_bytes().chunks_exact(2).map(|p|
        u8::from_str_radix(core::str::from_utf8(p).unwrap(),16).unwrap()).collect()
}
fn limits()->sha2::Limits {sha2::Limits {stack_bytes:262144,max_stack_mapping_bytes:1048576,
    max_output_mapping_bytes:65536,max_message_bits:100000,max_chunks:4096}}
fn check(a:A,bits:usize,bytes:&[u8],expected:&[u8]) {
    assert_eq!(bytes.len(),bits.div_ceil(8)); assert_eq!(expected.len(),a.output_bytes());
    let mut session=sha2::Session::new(a,limits()).unwrap();
    assert_eq!(session.algorithm(),a);
    let width=if bits==0 {0} else {((bits-1)%8+1) as u8};
    let cancel=sha2::Cancellation::new();
    let digest=session.hash_chunks(&[],bytes,width,&cancel).unwrap();
    assert_eq!(digest.algorithm(),a); assert_eq!(digest.expose(),expected); drop(digest);
    for stride in [1,19,128] {
        let chunks:Vec<_>=bytes[..bits/8].chunks(stride).collect();
        let digest=session.hash_chunks(&chunks,&bytes[bits/8..],(bits%8) as u8,&cancel).unwrap();
        assert_eq!(digest.algorithm(),a);
        let mut public=vec![0xa5;a.output_bytes()];
        digest.declassify(&mut public,sha2::PublicDeclassification::acknowledge()).unwrap();
        assert_eq!(public,expected);
    }
}
pub fn run() {
    let mut named=std::collections::BTreeMap::new();
    for row in include_str!("vectors/nist-bit-selected.txt").lines().filter(|r|!r.is_empty()&&!r.starts_with('#')) {
        let c:Vec<_>=row.split('|').collect(); assert_eq!(c.len(),4);
        let a=match c[0] {"SHA224"=>A::Sha224,"SHA256"=>A::Sha256,"SHA384"=>A::Sha384,
            "SHA512"=>A::Sha512,"SHA512_224"=>A::Sha512_224,"SHA512_256"=>A::Sha512_256,_=>panic!("unknown identity")};
        let bits:usize=c[1].parse().unwrap(); let message=hex(c[2]); let expected=hex(c[3]);
        if bits==0 {assert_eq!(message,[0]);} else {assert_eq!(message.len(),bits.div_ceil(8));}
        check(a,bits,&message[..bits.div_ceil(8)],&expected);
        *named.entry(c[0]).or_insert(0usize)+=1;
    }
    assert_eq!(named.len(),6); assert!(named.values().all(|n|*n==40));
    let mut rows=include_str!("vectors/general-sha512-t-digest.txt").lines();
    let mut count=0;
    for t in (1u16..512).filter(|t|*t!=384) {
        for bits in [0usize,24,889,898,1019,1028,1037,2046,2055] {
            let c:Vec<_>=rows.next().unwrap().split_whitespace().collect(); assert_eq!(c.len(),4);
            assert_eq!(c[0].parse::<u16>().unwrap(),t); assert_eq!(c[1].parse::<usize>().unwrap(),bits);
            let p=sha2::Sha512TBits::new(t).unwrap();
            check(A::Sha512T(p),bits,&hex(c[2]),&hex(c[3])); count+=1;
        }
    }
    assert!(rows.next().is_none()); assert_eq!(count,4590);
    println!("\nSTRICT_SHA2_BIT_ORACLE: 240 named; 4590 general-t; four input/output paths each");
}
'''
