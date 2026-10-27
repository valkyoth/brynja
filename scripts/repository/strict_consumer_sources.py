"""Public strict-facade scalar tests; reuse independent corpora, not leaf outputs."""
import legacy_execution_package as shared
import strict_consumer_bits


def replace_once(source, before, after):
    shared.require(source.count(before) == 1, 'strict consumer adapter anchor: ' + before)
    return source.replace(before, after)


# Fixtures come from the reviewed repository; runtime dependencies remain extracted archives.
def install(consumer, roots):
    hashes = shared.load('scripts/cryptography/macos_resident_oracle.py')
    keyed = shared.load('scripts/cryptography/macos_resident_keyed_oracle.py')
    shared.require(hashes.write_consumer(consumer) == 662, 'strict hash oracle population')
    shared.require(keyed.write_consumer(consumer) == 512, 'strict keyed oracle population')
    source = replace_once((consumer / 'src/families.rs').read_text(),
        'use brynja_crypto_cpu_std::macos_resident::{sha2,sha3};', 'use brynja_strict::{sha2,sha3};')
    source = replace_once(source, 'RESIDENT_FAMILY_ORACLE:', r'\nSTRICT_FAMILY_ORACLE:')
    (consumer / 'src/families.rs').write_text(source)
    source = replace_once((consumer / 'src/keyed.rs').read_text(),
        'use brynja_crypto_cpu_std::macos_resident::{kmac as k,tuplehash as t};',
        'use brynja_strict::{kmac as k,tuplehash as t};')
    for before in (
        '        check!(k::CompiledSession::new(a,k::Kernel::ArmKeccak,klimits())?);\n',
        '        let mut arm=t::CompiledSession::new(a,t::Kernel::ArmKeccak,tlimits())?;\n',
        '        assert_eq!(arm.compute(&items,custom(),&cancel)?.expose(),expected); count+=1;\n',
    ):
        source = replace_once(source, before, '')
    source = replace_once(source, 'assert_eq!(count,1024);', 'assert_eq!(count,512);')
    source = replace_once(source, 'RESIDENT_KEYED_ORACLE: 1024 passed; 512 scalar; 512 ArmKeccak',
                          r'\nSTRICT_KEYED_ORACLE: 512 passed; scalar')
    (consumer / 'src/keyed.rs').write_text(source)
    (consumer / 'src/bit_vectors.rs').write_text(strict_consumer_bits.SOURCE)
    (consumer / 'src/vectors').mkdir()
    for name in ('nist-bit-selected.txt', 'general-sha512-t-digest.txt'):
        (consumer / 'src/vectors' / name).write_bytes((shared.ROOT / 'crates/brynja-hash-sha2/tests/vectors' / name).read_bytes())
    (consumer / 'tests/acceptance.rs').write_text(SOURCE)


SOURCE = r'''
#![forbid(unsafe_code)]
use brynja_strict::{sha2,sha3,kmac,tuplehash};
#[path="../src/families.rs"] mod families;
#[path="../src/keyed.rs"] mod keyed;
#[path="../src/bit_vectors.rs"] mod bit_vectors;
#[test] fn hash_oracles() { families::run().unwrap(); }
#[test] fn keyed_oracles() { keyed::run().unwrap(); }
#[test] fn sha2_bit_oracles() { bit_vectors::run(); }
fn l2()->sha2::Limits {sha2::Limits{stack_bytes:262144,max_stack_mapping_bytes:1048576,
    max_output_mapping_bytes:65536,max_message_bits:24,max_chunks:2}}
fn l3()->sha3::Limits {sha3::Limits{stack_bytes:262144,max_stack_mapping_bytes:1048576,
    max_output_mapping_bytes:65536,max_message_bits:24,max_customization_bits:8,
    max_output_bits:512,max_chunks:2}}
fn lk()->kmac::Limits {kmac::Limits{stack_bytes:262144,max_stack_mapping_bytes:1048576,
    max_buffer_mapping_bytes:65536,max_message_bits:24,max_setup_bits:512,
    max_output_bits:512,max_chunks:2}}
fn lt()->tuplehash::Limits {tuplehash::Limits{stack_bytes:262144,max_stack_mapping_bytes:1048576,
    max_buffer_mapping_bytes:65536,max_input_bits:24,max_customization_bits:8,
    max_output_bits:512,max_items:2,max_chunks:2}}
// Copies here contain synthetic public fixtures, never application secrets.
// These tests observe public behavior, not inaccessible mapping/register residue.
#[test] fn sha2_lifecycle() {
    let a=sha2::Algorithm::Sha256;
    let mut s=sha2::Session::new(a,l2()).unwrap(); assert_eq!(s.algorithm(),a);
    let expected=s.hash(b"abc").unwrap().expose().to_vec();
    assert_eq!(s.hash_chunks(&[b"a",b"bc"],&[],0,&sha2::Cancellation::new()).unwrap().expose(),expected);
    let cancel=sha2::Cancellation::new(); cancel.cancel();
    assert!(matches!(s.hash_chunks(&[],&[],0,&cancel),Err(sha2::Error::Cancelled)));
    assert!(matches!(s.hash(b"abcd"),Err(sha2::Error::WorkLimit)));
    assert!(matches!(s.hash_chunks(&[],&[1],1,&sha2::Cancellation::new()),Err(sha2::Error::InvalidBits)));
    let mut public=[0xa5;31];
    assert_eq!(s.hash(b"abc").unwrap().declassify(&mut public,sha2::PublicDeclassification::acknowledge()),Err(sha2::Error::OutputLength));
    assert_eq!(public,[0xa5;31]);
    std::mem::forget(s.hash(b"abc").unwrap());
    assert_eq!(s.hash(b"abc").unwrap().expose(),expected);
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _loan=s.hash(b"abc").unwrap(); panic!("synthetic caller unwind");
    })); assert!(result.is_err());
    let mut public=[0;32];
    s.hash(b"abc").unwrap().declassify(&mut public,sha2::PublicDeclassification::acknowledge()).unwrap();
    assert_eq!(public.as_slice(),expected);
}
#[test] fn sha3_lifecycle() {
    let a=sha3::Algorithm::Shake128(257);
    let mut s=sha3::Session::new(a,l3()).unwrap(); assert_eq!(s.algorithm(),a);
    let expected=s.hash(b"abc").unwrap().expose().to_vec(); assert_eq!(expected[32]&0xfe,0);
    assert_eq!(s.hash_chunks(&[b"a",b"bc"],sha3::Bits::empty(),&sha3::Cancellation::new()).unwrap().expose(),expected);
    let cancel=sha3::Cancellation::new(); cancel.cancel();
    assert!(matches!(s.hash_chunks(&[],sha3::Bits::empty(),&cancel),Err(sha3::Error::Cancelled)));
    assert!(matches!(s.hash(b"abcd"),Err(sha3::Error::WorkLimit)));
    assert!(matches!(s.hash_chunks(&[],sha3::Bits{bytes:&[0x80],valid_bits:1},&sha3::Cancellation::new()),Err(sha3::Error::InvalidBits)));
    let mut public=[0xa5;32];
    assert_eq!(s.hash(b"abc").unwrap().declassify(&mut public,sha3::PublicDeclassification::acknowledge()),Err(sha3::Error::OutputLength));
    assert_eq!(public,[0xa5;32]);
    std::mem::forget(s.hash(b"abc").unwrap());
    assert_eq!(s.hash(b"abc").unwrap().expose(),expected);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _loan=s.hash(b"abc").unwrap(); panic!("synthetic caller unwind");
    })).is_err());
    let mut public=[0;33];
    s.hash(b"abc").unwrap().declassify(&mut public,sha3::PublicDeclassification::acknowledge()).unwrap();
    assert_eq!(public.as_slice(),expected);
}
#[test] fn kmac_lifecycle() {
    let a=kmac::Algorithm::Kmac128(256); let key=[0x42;32];
    let mut s=kmac::Session::new(a,lk()).unwrap(); assert_eq!(s.algorithm(),a);
    let expected=s.authenticate(&key,b"abc",b"").unwrap().expose().to_vec();
    let chunks:&[&[u8]]=&[b"a",b"bc"];
    let request=||kmac::Request{key:kmac::Bits::bytes(&key),customization:kmac::Bits::empty(),
        chunks,tail:kmac::Bits::empty()};
    assert_eq!(s.compute(request(),&kmac::Cancellation::new()).unwrap().expose(),expected);
    let cancel=kmac::Cancellation::new(); cancel.cancel();
    assert!(matches!(s.compute(request(),&cancel),Err(kmac::Error::Cancelled)));
    assert!(matches!(s.authenticate(&key,b"abcd",b""),Err(kmac::Error::WorkLimit)));
    assert!(s.authenticate(&[],b"abc",b"").is_err());
    assert!(s.verify(request(),kmac::Bits::bytes(&expected),&kmac::Cancellation::new()).unwrap());
    let mut wrong=expected.clone(); wrong[0]^=1;
    assert!(!s.verify(request(),kmac::Bits::bytes(&wrong),&kmac::Cancellation::new()).unwrap());
    let mut public=[0xa5;31];
    assert_eq!(s.authenticate(&key,b"abc",b"").unwrap().declassify(&mut public,kmac::PublicDeclassification::acknowledge()),Err(kmac::Error::OutputLength));
    assert_eq!(public,[0xa5;31]);
    std::mem::forget(s.authenticate(&key,b"abc",b"").unwrap());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _loan=s.authenticate(&key,b"abc",b"").unwrap(); panic!("synthetic caller unwind");
    })).is_err());
    let mut public=[0;32];
    s.authenticate(&key,b"abc",b"").unwrap().declassify(&mut public,kmac::PublicDeclassification::acknowledge()).unwrap();
    assert_eq!(public.as_slice(),expected);
}
#[test] fn tuplehash_lifecycle() {
    let a=tuplehash::Algorithm::TupleHash128(257);
    let mut s=tuplehash::Session::new(a,lt()).unwrap(); assert_eq!(s.algorithm(),a);
    let items=[tuplehash::Item{chunks:&[b"abc"],tail:tuplehash::Bits::empty()}];
    let expected=s.hash(&items,b"").unwrap().expose().to_vec(); assert_eq!(expected[32]&0xfe,0);
    let split=[tuplehash::Item{chunks:&[b"a",b"bc"],tail:tuplehash::Bits::empty()}];
    assert_eq!(s.hash(&split,b"").unwrap().expose(),expected);
    let cancel=tuplehash::Cancellation::new(); cancel.cancel();
    assert!(matches!(s.compute(&items,tuplehash::Bits::empty(),&cancel),Err(tuplehash::Error::Cancelled)));
    let big=[tuplehash::Item{chunks:&[b"abcd"],tail:tuplehash::Bits::empty()}];
    assert!(matches!(s.hash(&big,b""),Err(tuplehash::Error::WorkLimit)));
    let malformed=[tuplehash::Item{chunks:&[],tail:tuplehash::Bits{bytes:&[0x80],valid_bits:1}}];
    assert!(matches!(s.hash(&malformed,b""),Err(tuplehash::Error::InvalidBits)));
    let mut public=[0xa5;32];
    assert_eq!(s.hash(&items,b"").unwrap().declassify(&mut public,tuplehash::PublicDeclassification::acknowledge()),Err(tuplehash::Error::OutputLength));
    assert_eq!(public,[0xa5;32]);
    std::mem::forget(s.hash(&items,b"").unwrap());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _loan=s.hash(&items,b"").unwrap(); panic!("synthetic caller unwind");
    })).is_err());
    let mut public=[0;33];
    s.hash(&items,b"").unwrap().declassify(&mut public,tuplehash::PublicDeclassification::acknowledge()).unwrap();
    assert_eq!(public.as_slice(),expected);
}
'''


def mutations():
    result = []
    for family in ('sha2', 'sha3', 'kmac', 'tuplehash'):
        result.append((f'strict_{family}/types.rs', 'if self.0.load(Ordering::Acquire) {',
                       'if false {', family + '_lifecycle'))
        budget = 'max_input_bits' if family == 'tuplehash' else 'max_message_bits'
        anchor = 'if bits > limits.' + budget + ' {'
        result.append((f'strict_{family}/mod.rs', anchor, 'if false {', family + '_lifecycle'))
        result.append((f'strict_{family}/mod.rs', 'self.output.as_bytes()\n', '&[]\n',
                       'hash_oracles' if family in ('sha2', 'sha3') else 'keyed_oracles'))
        copy = 'destination.copy_from_slice(' + ('self.output.as_bytes()' if family == 'sha2' else 'self.expose()') + ');'
        result.append((f'strict_{family}/mod.rs', copy, 'let _ = destination;', family + '_lifecycle'))
    return result


def request(family):
    return {'sha2': 'hash(b"abc")', 'sha3': 'hash(b"abc")',
            'kmac': 'authenticate(&[0x42;32],b"abc",b"")',
            'tuplehash': 'hash(&[],b"")'}[family]
