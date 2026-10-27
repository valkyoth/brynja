"""Public owned/scoped hardened legacy acceptance; no private storage inspection."""
import json
import re

import legacy_execution_package as shared
import legacy_hardened_cases as cases
from facade_tuplehash_probes import diagnostic


def install(consumer, roots, family):
    shared.install(consumer, roots, family)
    manifest = consumer / 'Cargo.toml'
    text = manifest.read_text().replace('execution=[]\nruntime-execution=[]',
                                       'hardened-execution=[]\nruntime-hardened-execution=[]')
    text = text.replace('features=["execution"]', 'features=["execution","hardened-execution"]')
    text = text.replace('features=["runtime-execution"]', 'features=["runtime-hardened-execution"]')
    manifest.write_text(text)
    leaf = 'brynja-legacy-' + family
    for name, package in (('execution', leaf), ('hosted', leaf + '-std')):
        (consumer / f'tests/{name}.rs').write_bytes((shared.ROOT / 'crates' / package / 'tests/hardened_execution.rs').read_bytes())
    (consumer / 'tests/selection.rs').write_text(shared.cases.selection(family).replace('execution', 'hardened_execution'))
    (consumer / 'tests/scope.rs').write_text(cases.scope(family))
    if family == 'sha1':
        # Reuse the existing generator unchanged. Its support copies are not
        # compiled; integration tests above are repository fixtures against extracted libraries.
        scratch = consumer / 'oracle-generator'
        (scratch / 'src').mkdir(parents=True)
        (scratch / 'src/lib.rs').write_text('')
        shared.load('scripts/sha1/hardened_package.py').prepare(shared.ROOT, scratch)
        source = (scratch / 'tests/oracle.rs').read_text()
        validate_oracle(source)
        (consumer / 'tests/oracle.rs').write_text(source)
    else:
        (consumer / 'src/main.rs').write_bytes((shared.ROOT / 'assurance/md5-hardened-execution/src/main.rs').read_bytes())


def validate_oracle(source):
    # Count data tuples, not the similarly spelled (&[u8], ...) type declaration.
    rows = re.findall(r'\(&\[[\d, ]*\], [0-8], \[[\d, ]+\]\)', source)
    shared.require(len(rows) == 1135, 'hardened SHA-1 oracle population')


def negatives(api, consumer, cargo, env, family):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    count = 0
    try:
        for owner in cases.owners(family):
            typename = f'brynja_legacy_{family}::hardened_execution::{owner}'
            path.write_text(f'pub fn present(_:Option<{typename}>) {{}}')
            api.run(cargo + ['check', '--offline', '--lib'], consumer, env)
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                path.write_text(f'fn bound<T:{bound}>() {{}} fn probe() {{bound::<{typename}>();}}')
                result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
                shared.require(diagnostic(result, 'E0277'), 'hardened owner diagnostic')
                count += 1
        for text, code in cases.negatives(family):
            path.write_text(text)
            result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
            valid = diagnostic(result, code) if code else result.returncode == 101 and 'lifetime may not live long enough' in result.stdout
            shared.require(valid, 'hardened lifetime/classification diagnostic')
            count += 1
    finally:
        path.write_text(original)
    shared.require(count == (34 if family == 'sha1' else 31), 'hardened negative population')
    print(f'PASS: isolated hardened {family}: {count} ownership/scope/classification rejections', flush=True)


def execute(api, root, roots, cargo, env, family, native):
    consumer = root / (family + '-hardened-consumer')
    install(consumer, roots, family)
    generic = dict(env, CARGO_TARGET_DIR=str(root / (family + '-hardened-target')))
    metadata = api.run(cargo + ['metadata', '--offline', '--all-features', '--format-version=1'], consumer, generic)
    shared.graph(api, json.loads(metadata.stdout), roots, consumer, family, hardened=True)
    shared.campaign(api, consumer, cargo, generic, family, False, hardened=True)
    negatives(api, consumer, cargo, generic, family)
    shared.mutants(api, consumer, roots, cargo, generic, family, False, hardened=True)
    if native:
        probe = api.run(cargo + ['run', '--offline', '--bin', 'probe'], consumer, generic)
        accelerated = dict(generic, RUSTFLAGS='-C target-feature=' + shared.native_flags(probe.stdout, family),
                           CARGO_TARGET_DIR=str(root / (family + '-hardened-native-target')))
        shared.campaign(api, consumer, cargo, accelerated, family, True, hardened=True)
        shared.mutants(api, consumer, roots, cargo, accelerated, family, True, hardened=True)
