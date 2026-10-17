"""Route-separated public consumers adapted from the strict scalar corpora."""
import strict_consumer_sources as scalar
from legacy_execution_package import require

ROUTES = ('narrow', 'wide', 'keccak')
FAMILIES = {'narrow': ('sha2',), 'wide': ('sha2',), 'keccak': ('sha3', 'kmac', 'tuplehash')}
COUNTS = {'narrow': (30, 80, 0), 'wide': (60, 160, 4590), 'keccak': (572, 0, 0)}
once = scalar.replace_once


def constructors(text):
    for family, alias in (('sha2', 'sha2'), ('sha3', 'sha3'), ('kmac', 'k'), ('tuplehash', 't')):
        text = text.replace(alias + '::Session::new(', 'crate::route::' + family + '(')
    return text


def markers(route):
    count, named, general = COUNTS[route]
    values = [f'STRICT_ACCELERATED_HASH: {route}; {count} passed']
    if route == 'keccak':
        values += ['STRICT_ACCELERATED_KEYED: 512 passed']
    else:
        values += [f'STRICT_ACCELERATED_BITS: {route}; {named} named; {general} general-t']
    return values


def install(consumer, route):
    require(route in ROUTES, 'unknown strict accelerated route')
    names = {'narrow': {'sha224', 'sha256'}, 'wide': {'sha384', 'sha512', 'sha512_224', 'sha512_256'},
             'keccak': {'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'shake_128', 'shake_256'}}[route]
    path = consumer / 'src/hashes.txt'
    rows = [row for row in path.read_text().splitlines() if row.split()[0] in names]
    require(len(rows) == len(names) * 15 and {row.split()[0] for row in rows} == names, 'accelerated hash corpus partition')
    path.write_text('\n'.join(rows) + '\n')
    if route != 'keccak':
        (consumer / 'src/cshake.txt').write_text('')
    path = consumer / 'src/families.rs'
    body = constructors(path.read_text())
    body = once(body, 'assert_eq!(count,662);', f'assert_eq!(count,{COUNTS[route][0]});')
    body = once(body, 'STRICT_FAMILY_ORACLE: {count} passed', f'STRICT_ACCELERATED_HASH: {route}; {{count}} passed')
    path.write_text(body)
    if route == 'keccak':
        path = consumer / 'src/keyed.rs'
        body = constructors(path.read_text())
        body = once(body, 'STRICT_KEYED_ORACLE: 512 passed; scalar', 'STRICT_ACCELERATED_KEYED: 512 passed')
        path.write_text(body)
    else:
        path = consumer / 'src/vectors/nist-bit-selected.txt'
        selected = {n.upper() for n in names}
        rows = [row for row in path.read_text().splitlines() if row.split('|')[0] in selected]
        require(len(rows) == COUNTS[route][1], 'accelerated named bit corpus partition')
        path.write_text('\n'.join(rows) + '\n')
        path = consumer / 'src/bit_vectors.rs'
        body = constructors(path.read_text())
        body = once(body, 'assert_eq!(named.len(),6);', f'assert_eq!(named.len(),{len(names)});')
        if route == 'narrow':
            body = once(body, '(1u16..512)', '(1u16..1)')
            body = once(body, 'assert_eq!(count,4590);', 'assert_eq!(count,0);')
            (consumer / 'src/vectors/general-sha512-t-digest.txt').write_text('')
        body = once(body, 'STRICT_SHA2_BIT_ORACLE: 240 named; 4590 general-t; four input/output paths each', markers(route)[1])
        path.write_text(body)
    (consumer / 'src/route.rs').write_text(ROUTE_SOURCE)
    (consumer / 'tests/acceptance.rs').write_text(lifecycle(route))
    (consumer / 'tests/admission.rs').write_text(admission(route))
    (consumer / 'src/bin').mkdir()
    (consumer / 'src/bin/cpu.rs').write_text(PROBE)


def lifecycle(route):
    text = scalar.SOURCE
    start, end = text.index('fn l2()'), text.index('#[test] fn sha2_lifecycle()')
    body = '#![forbid(unsafe_code)]\nuse brynja_strict::{sha2,sha3,kmac,tuplehash};\n'
    body += '#[path="../src/route.rs"] mod route;\n#[path="../src/families.rs"] mod families;\n'
    body += '#[test] fn hash_oracles(){families::run().unwrap();}\n'
    if route == 'keccak':
        body += '#[path="../src/keyed.rs"] mod keyed;\n#[test] fn keyed_oracles(){keyed::run().unwrap();}\n'
    else:
        body += '#[path="../src/bit_vectors.rs"] mod bit_vectors;\n#[test] fn sha2_bit_oracles(){bit_vectors::run();}\n'
    body += text[start:end]
    functions = text[end:].split('#[test] fn ')[1:]
    require(len(functions) == 4, 'strict lifecycle population')
    for family, function in zip(('sha2', 'sha3', 'kmac', 'tuplehash'), functions):
        require(function.startswith(family + '_lifecycle() {') and function.rstrip().endswith('}'), 'strict lifecycle identity')
        if family not in FAMILIES[route]:
            continue
        function = function.replace(family + '::Session::new(', 'crate::route::' + family + '(')
        if route == 'wide':
            function = once(function, 'sha2::Algorithm::Sha256', 'sha2::Algorithm::Sha512')
            function = function.replace('[0xa5;31]', '[0xa5;63]').replace('[0;32]', '[0;64]')
        function = function.rstrip()[:-1]
        function += f'''assert!(!s.is_quarantined());
    s.quarantine(); assert!(s.is_quarantined());
    assert!(matches!(s.{scalar.request(family)},Err({family}::Error::Quarantined)));
}}\n'''
        body += '#[test] fn ' + function
    return body


def admission(route):
    result = '#![forbid(unsafe_code)]\n#[path="../src/route.rs"] mod route;\n'
    result += 'use brynja_strict::{sha2,sha3,kmac,tuplehash};\n'
    result += scalar.SOURCE[scalar.SOURCE.index('fn l2()'):scalar.SOURCE.index('// Copies here')]
    result += '#[test] fn admission(){\n'
    for family in FAMILIES[route]:
        algorithm, limits = {'sha2': ('Sha256' if route == 'narrow' else 'Sha512', 'l2()'),
                             'sha3': ('Sha3_256', 'l3()'), 'kmac': ('Kmac128(256)', 'lk()'),
                             'tuplehash': ('TupleHash128(256)', 'lt()')}[family]
        kernel = f'route::kernel("{route}")'
        wrong_op = 'X86Keccak' if family == 'sha2' else 'X86Sha256'
        wrong_arch = {'narrow': ('ArmSha256', 'X86Sha256'), 'wide': ('ArmSha512', 'X86Sha512'),
                      'keccak': ('ArmKeccak', 'X86Keccak')}[route]
        result += f'''{{
    let a={family}::Algorithm::{algorithm}; let k={kernel};
    match {family}::CompiledSession::new(a,k,{limits}) {{
        Ok(s)=>{{assert!(route::ready("{route}")); assert_eq!(s.kernel(),k); assert!(!s.is_quarantined());}},
        Err(e)=>{{assert!(!route::ready("{route}")); assert_eq!(format!("{{e:?}}"),"Backend(MissingTargetFeatures)");}}
    }}
    let wrong=if cfg!(target_arch="x86_64") {{sha2::Kernel::{wrong_arch[0]}}} else {{sha2::Kernel::{wrong_arch[1]}}};
    let e={family}::CompiledSession::new(a,wrong,{limits}).err().expect("foreign architecture admitted");
    assert_eq!(format!("{{e:?}}"),"Backend(WrongArchitecture)");
    let e={family}::CompiledSession::new(a,sha2::Kernel::{wrong_op},{limits}).err().expect("wrong operation admitted");
    assert_eq!(format!("{{e:?}}"),"Backend(WrongOperation)");
}}\n'''
    result += f'println!("\\nSTRICT_COMPILED_ADMISSION: {route}; ready={{}}",route::ready("{route}"));\n}}\n'
    return result


ROUTE_SOURCE = r'''
use brynja_strict::{sha2,sha3,kmac,tuplehash};
pub fn kernel(route:&str)->sha2::Kernel {
    match (cfg!(target_arch="x86_64"),route) {
        (true,"narrow")=>sha2::Kernel::X86Sha256,(true,"wide")=>sha2::Kernel::X86Sha512,
        (true,"keccak")=>sha2::Kernel::X86Keccak,(false,"narrow")=>sha2::Kernel::ArmSha256,
        (false,"wide")=>sha2::Kernel::ArmSha512,(false,"keccak")=>sha2::Kernel::ArmKeccak,_=>panic!("route")
    }
}
pub fn ready(route:&str)->bool {
    match route {
        "narrow"=>cfg!(any(all(target_arch="x86_64",target_feature="sha",target_feature="sse2"),
                         all(target_arch="aarch64",target_feature="neon",target_feature="sha2"))),
        "wide"=>cfg!(any(all(target_arch="x86_64",target_feature="sha512",target_feature="avx2",target_feature="avx"),
                       all(target_arch="aarch64",target_feature="neon",target_feature="sha3"))),
        "keccak"=>cfg!(any(all(target_arch="x86_64",target_feature="avx2",target_feature="avx"),
                         all(target_arch="aarch64",target_feature="neon",target_feature="sha3"))),_=>panic!("route")
    }
}
pub fn sha2(a:sha2::Algorithm,l:sha2::Limits)->Result<sha2::CompiledSession,sha2::Error> {
    let route=if matches!(a,sha2::Algorithm::Sha224|sha2::Algorithm::Sha256){"narrow"}else{"wide"};
    let k=kernel(route); let s=sha2::CompiledSession::new(a,k,l)?;
    assert_eq!(s.kernel(),k); assert_eq!(s.algorithm(),a); Ok(s)
}
macro_rules! make {($name:ident)=>{
    pub fn $name(a:$name::Algorithm,l:$name::Limits)->Result<$name::CompiledSession,$name::Error> {
        let k=kernel("keccak"); let s=$name::CompiledSession::new(a,k,l)?;
        assert_eq!(s.kernel(),k); assert_eq!(s.algorithm(),a); Ok(s)
    }
}}
make!(sha3); make!(kmac); make!(tuplehash);
'''

PROBE = r'''
#![forbid(unsafe_code)]
fn main(){
    #[cfg(target_arch="x86_64")]
    let (n,w,k)=(std::arch::is_x86_feature_detected!("sha")&&std::arch::is_x86_feature_detected!("sse2"),
        std::arch::is_x86_feature_detected!("sha512")&&std::arch::is_x86_feature_detected!("avx2")&&std::arch::is_x86_feature_detected!("avx"),
        std::arch::is_x86_feature_detected!("avx2")&&std::arch::is_x86_feature_detected!("avx"));
    #[cfg(target_arch="aarch64")]
    let (n,w,k)=(std::arch::is_aarch64_feature_detected!("neon")&&std::arch::is_aarch64_feature_detected!("sha2"),
        std::arch::is_aarch64_feature_detected!("neon")&&std::arch::is_aarch64_feature_detected!("sha3"),
        std::arch::is_aarch64_feature_detected!("neon")&&std::arch::is_aarch64_feature_detected!("sha3"));
    println!("CPU:{}:{n}:{w}:{k}",std::env::consts::ARCH);
}
'''
