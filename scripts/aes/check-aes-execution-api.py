#!/usr/bin/env python3
"""Paired compiler diagnostics for static/runtime AES ownership and admission."""
import argparse
import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('aes_api', Path(__file__).with_name('check-aes-api.py'))
API = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(API)


def diagnostic_matches(result, expected, source):
    code, count = expected if isinstance(expected, tuple) else (expected, 1)
    try:
        errors = []
        for line in result.stderr.splitlines():
            row = json.loads(line)
            if row.get('$message_type') != 'diagnostic' or row.get('level') != 'error':
                continue
            if row.get('code') is None and not row.get('spans') and row.get('message', '').startswith('aborting due to '):
                continue
            errors.append(row)
        return result.returncode == 1 and len(errors) == count and all(
            (row.get('code') or {}).get('code') == code and any(
                span.get('is_primary') and span.get('file_name') == str(source)
                for span in row.get('spans', [])) for row in errors)
    except (ValueError, AttributeError):
        return False


# Borrowed authorities can yield several independent Send/Sync diagnostics.
# Pin the complete diagnostic population, never accept an unrelated build error.
API.diagnostic_matches = diagnostic_matches


def probes():
    prefix = 'use brynja_crypto::aes::execution::*;\n'
    cases = []
    for bits, size, expanded in ((128, 16, 176), (192, 24, 208), (256, 32, 240)):
        for suffix, storage in (('Key', size), ('ExpandedKey', expanded)):
            owner = f'Aes{bits}{suffix}'
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                negative = prefix + f"fn need<T:{bound}>(){{}} fn main(){{need::<{owner}<'static,'static>>();}}"
                cases.append((owner + '-' + bound, negative, negative.replace('T:' + bound, 'T'),
                              ('E0277', 3) if bound in ('Send', 'Sync') else 'E0277'))
            start = prefix + f'fn main(){{let a=Authority::new(Kernel::X86AesNi).unwrap(); let mut s=[0;{storage}]; let k={owner}::new(&a,&[0;{size}],&mut s).unwrap(); '
            cases.append((owner + '-storage', start + 's.fill(1); let _=k.report();}',
                          start + 'k.clear(); s.fill(1);}', 'E0499'))
            negative = prefix + f'fn main(){{let mut s=[0;{storage}]; let k; {{let a=Authority::new(Kernel::X86AesNi).unwrap(); k={owner}::new(&a,&[0;{size}],&mut s).unwrap();}} let _=k.report();}}'
            cases.append((owner + '-authority-lifetime', negative, start + 'let _=k.report();}', 'E0597'))
    for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
        negative = prefix + f'fn need<T:{bound}>(){{}} fn main(){{need::<Authority>();}}'
        cases.append(('authority-' + bound, negative, negative.replace('T:' + bound, 'T'),
                      ('E0277', 3) if bound == 'Sync' else 'E0277'))
    cases += [
        ('unsafe-platform-obligation', prefix + 'fn main(){let _=Authority::from_platform(Kernel::X86AesNi);}',
         prefix + 'fn main(){unsafe{let _=Authority::from_platform(Kernel::X86AesNi);}}', 'E0133'),
        ('report-not-authority', prefix + 'fn forge(r:Report)->Authority{r.into()} fn main(){}',
         prefix + 'fn forge(r:Report)->Report{r} fn main(){}', 'E0277'),
    ]
    for bits, size, expanded in ((128, 16, 176), (192, 24, 208), (256, 32, 240)):
        start = prefix + 'fn probe(a:&Authority){let s=a.session().unwrap(); '
        end = '} fn main(){}'
        good = start + f'let _=s.expand{bits}(&[0;{size}],&mut[0;{expanded}]);' + end
        cases.append((f'expansion-{bits}-key-width', start + f'let _=s.expand{bits}(&[0;{size-1}],&mut[0;{expanded}]);' + end, good, 'E0308'))
        cases.append((f'expansion-{bits}-schedule-width', start + f'let _=s.expand{bits}(&[0;{size}],&mut[0;{expanded-1}]);' + end, good, 'E0308'))
        borrowed = start + f'let mut b=[0;{size+expanded}]; '
        negative = borrowed + f'let key=(&b[..{size}]).try_into().unwrap(); let out=(&mut b[..{expanded}]).try_into().unwrap(); let _=s.expand{bits}(key,out);' + end
        positive = borrowed + f'let (key,out)=b.split_at_mut({size}); let _=s.expand{bits}((&*key).try_into().unwrap(),out.try_into().unwrap());' + end
        cases.append((f'expansion-{bits}-alias', negative, positive, 'E0502'))
    assert len(cases) == 58
    return cases


def run(tc):
    total = 0
    groups = []
    for package, path in (('brynja-crypto', 'brynja_crypto'), ('brynja', 'brynja::crypto')):
        groups.append((package, 'aes-runtime-execution', [(name, neg.replace('brynja_crypto', path), pos.replace('brynja_crypto', path), code)
                                                         for name, neg, pos, code in probes()]))
        prefix = f'use {path}::aes::execution::*; '
        groups.append((package, 'aes-static-execution', [('runtime-default-off',
            prefix + 'fn main(){unsafe{let _=Authority::from_platform(Kernel::X86AesNi);}}',
            prefix + 'fn main(){let _=Authority::new(Kernel::X86AesNi);}', 'E0599')]))
        groups.append((package, 'hazmat-aes-block', [('execution-default-off',
            prefix + 'fn main(){}', f'fn main(){{let _={path}::aes::Aes128Key::new(&[0;16],&mut[0;16]);}}', 'E0432')]))
    prefix = 'use brynja_crypto_cpu_std::aes::{Authority,Kernel,Mode}; '
    hosted = []
    for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
        neg = prefix + f'fn need<T:{bound}>(){{}} fn main(){{need::<Authority>();}}'
        hosted.append(('hosted-' + bound, neg, neg.replace('T:' + bound, 'T'),
                       ('E0277', 3) if bound == 'Sync' else 'E0277'))
    start = prefix + 'fn main(){let a=Authority::new(Kernel::ArmAes,Mode::Portable).unwrap(); '
    hosted += [
        ('hosted-private-owner', start + 'let _=a.owner;}', start + 'let _=a.report();}', 'E0616'),
        ('hosted-borrow-lifetime', prefix + 'fn main(){let k; {let a=Authority::new(Kernel::ArmAes,Mode::Portable).unwrap(); k=a.kernel_authority().unwrap();} let _=k.is_some();}',
         start + 'let k=a.kernel_authority().unwrap(); let _=k.is_some();}', 'E0597'),
    ]
    groups.append(('brynja-crypto-cpu-std', 'aes-runtime-execution', hosted))
    for index, (package, feature, cases) in enumerate(groups):
        with API.verifier.cargo_environment.private_directory(API.verifier.ROOT) as temporary:
            directory = Path(temporary)
            env = API.verifier.environment(directory)
            env.update(RUSTUP_AUTO_INSTALL='0', CARGO_NET_OFFLINE='true')
            API.run_probes(tc, directory, env, cases=cases, features=feature, package=package,
                           label=f'AES_EXECUTION_API_{index}')
            total += len(cases)
    assert total == 127
    print(f'AES_EXECUTION_API_PASS: {tc} 127 paired probes', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('toolchain', choices=API.TOOLCHAINS)
    run(parser.parse_args().toolchain)
