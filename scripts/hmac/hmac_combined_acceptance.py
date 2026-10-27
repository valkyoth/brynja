"""Co-installed modern/legacy HMAC archives, without adding a facade legacy edge."""
import json
from pathlib import Path
import tomllib

import hmac_acceptance

LEGACY = {'brynja-core', 'brynja-hash-core', 'brynja-legacy-sha1',
          'brynja-legacy-md5', 'brynja-legacy-hmac'}
ADDITIONAL = ('brynja-legacy-sha1', 'brynja-legacy-md5', 'brynja-legacy-hmac')
PARAMETERS = tuple(t for t in range(128, 512) if t != 384)


def general_parameters():
    return ('#[test]\nfn all_admitted_general_parameters() -> Result<(), Error> {\n'
            + ''.join(f'identity::<Sha512T<{t}>>()?;\n' for t in PARAMETERS) + 'Ok(())\n}\n')


def require(condition, message):
    if not condition:
        raise ValueError('combined HMAC acceptance: ' + message)


def indexed(document):
    packages = {p['id']: p for p in document['packages']}
    nodes = {n['id']: n for n in document['resolve']['nodes']}
    require(len(packages) == len(document['packages']) == len(nodes)
            == len(document['resolve']['nodes']) and set(packages) == set(nodes),
            'duplicate/missing graph identity')
    require(len({p['name'] for p in packages.values()}) == len(packages), 'duplicate package name')
    for node in nodes.values():
        require(len(node['dependencies']) == len(set(node['dependencies']))
                and set(node['dependencies']) == {d['pkg'] for d in node['deps']},
                'dependency representations disagree')
        require(len(node['features']) == len(set(node['features'])), 'duplicate feature')
        for dep in node['deps']:
            require(dep['pkg'] in nodes and dep['dep_kinds']
                    and all(k['kind'] in (None, 'build', 'dev') for k in dep['dep_kinds']),
                    'missing dependency or kind')
    require(document['resolve']['root'] in packages, 'missing consumer root')
    return packages, nodes


def closure(start, nodes):
    seen, pending = set(), [start]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(d['pkg'] for d in nodes[current]['deps']
                       if any(k['kind'] != 'dev' for k in d['dep_kinds']))
    return seen


def projection(identity, packages, nodes):
    node = nodes[identity]
    return (sorted(node['features']), sorted(
        (d['name'], packages[d['pkg']]['name'], json.dumps(d['dep_kinds'], sort_keys=True))
        for d in node['deps']))


def graph(document, baseline, roots, consumer, versions, facade):
    packages, nodes = indexed(document)
    old_packages, old_nodes = indexed(baseline)
    by_name = {p['name']: i for i, p in packages.items()}
    old_names = {p['name']: i for i, p in old_packages.items()}
    require(not set(old_names).intersection(ADDITIONAL), 'legacy in modern-only baseline')
    require(set(by_name) == set(old_names) | LEGACY, 'unexpected combined package closure')
    require(by_name.get('facade-consumer') == document['resolve']['root']
            and old_names.get('facade-consumer') == baseline['resolve']['root'], 'wrong consumer root')
    root_deps = nodes[document['resolve']['root']]['deps']
    require(len(root_deps) == 2 and
            {(d['name'], packages[d['pkg']]['name']) for d in root_deps}
            == {('facade', facade), ('legacy', 'brynja-legacy-hmac')}
            and all(d['dep_kinds'] == [{'kind': None, 'target': None}] for d in root_deps),
            'legacy must be a separate explicit consumer dependency')
    require({packages[i]['name'] for i in closure(by_name['brynja-legacy-hmac'], nodes)} == LEGACY,
            'legacy implementation closure changed')
    for name, old_id in old_names.items():
        if name != 'facade-consumer':
            require(projection(by_name[name], packages, nodes)
                    == projection(old_id, old_packages, old_nodes), 'modern edge/feature drift: ' + name)
    require(not any('conformance-testing' in n['features'] for n in nodes.values()),
            'conformance feature in consumer')
    paths = {**roots, 'facade-consumer': consumer}
    expected_versions = {**versions, 'facade-consumer': '0.0.0'}
    for package in packages.values():
        name = package['name']
        require(name in paths and name in expected_versions, 'unregistered archive')
        root = paths[name].resolve()
        require(package['version'] == expected_versions[name] and package['source'] is None
                and Path(package['manifest_path']).resolve() == root / 'Cargo.toml',
                'archive identity/source/path changed')
        require(not package.get('links') and package['targets'], 'native or absent targets')
        for target in package['targets']:
            require(not {'custom-build', 'proc-macro'}.intersection(target['kind'])
                    and Path(target['src_path']).resolve().is_relative_to(root),
                    'build hook or escaped target')


def negatives():
    for legacy in ('Md5', 'Sha1'):
        yield (f'pub fn probe(_: api::hmac::Hmac<legacy::{legacy}>) {{}}', 'E0277')
    yield ('pub fn probe(_: legacy::Hmac<api::hmac::Sha256>) {}', 'E0277')
    yield ('pub fn probe(_: api::hmac::Hmac<api::Sha256>) {}', 'E0277')
    for kind in ('Tag', 'SecretTag'):
        # Equal widths do not make tag identity or secret/public ownership interchangeable.
        modern = f'api::hmac::{kind}<\'a, api::hmac::Sha512T<128>>'
        legacy = f'legacy::{kind}<\'a, legacy::Md5>'
        yield (f'pub fn probe<\'a>(tag: {modern}) -> {legacy} {{tag}}', 'E0308')
        yield (f'pub fn probe<\'a>(tag: {legacy}) -> {modern} {{tag}}', 'E0308')
    yield ('pub fn probe<\'a>(digest: api::Sha256Digest) -> api::hmac::Tag<\'a, api::hmac::Sha256> {digest}', 'E0308')
    yield ('pub fn probe() {let _ = legacy::Hmac::<legacy::Sha1>::new(b"key");}', 'E0061')
    yield ('pub use api::hmac::Md5;', 'E0432')
    yield ('pub use api::hmac::Sha1;', 'E0432')


def execute(api, roots, consumer, cargo, env, bare_target):
    versions = {name: tomllib.loads((path / 'Cargo.toml').read_text())['package']['version']
                for name, path in roots.items()}
    modern = (api.ROOT / 'assurance/hmac-facade/acceptance.rs').read_text()
    legacy = (api.ROOT / 'assurance/hmac-facade/legacy.rs').read_text()
    extra = ('legacy={package="brynja-legacy-hmac", version="=' + versions['brynja-legacy-hmac']
             + '", default-features=false}\n')
    for facade in ('brynja-crypto', 'brynja'):
        api.manifest(consumer, roots, facade, [])
        api.source(consumer, facade, modern)
        baseline = json.loads(api.resolved_metadata(cargo, consumer, env, roots).stdout)
        api.graph(baseline, [])  # Independently prove the modern-only baseline first.
        api.manifest(consumer, roots, facade, [], extra=extra)
        api.source(consumer, facade, modern + '\n' + legacy + '\n' + general_parameters())
        metadata = json.loads(api.run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env).stdout)
        graph(metadata, baseline, roots, consumer, versions, facade)
        for profile in ([], ['--release']):
            api.test_run(cargo, consumer, env, 8, profile)
        # Positive type availability precedes every set of forbidden substitutions.
        positive = ('pub fn modern(_: api::hmac::Hmac<api::hmac::Sha512T<128>>) {}\n'
                    'pub fn legacy(_: legacy::Hmac<legacy::Md5>, _: legacy::Hmac<legacy::Sha1>) {}\n')
        api.source(consumer, facade, positive)
        api.run(cargo + ['build', '--offline', '--locked', '--target', bare_target], consumer, env)
        count = 0
        for body, diagnostic in negatives():
            api.source(consumer, facade, body)
            hmac_acceptance.diagnostic_rejection(api.run(cargo + ['check', '--offline', '--locked',
                '--message-format=json'], consumer, env, success=False), diagnostic)
            count += 1
        print(f'{facade}: co-installed modern/legacy runtime ({len(PARAMETERS)} general parameters), '
              f'no_std and {count} separation negatives PASS', flush=True)
