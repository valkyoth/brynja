"""Bind legacy host routes to the shared, source-reviewed thread lifecycle.

Only presentation names of the exact MD5 validator and resident buffer clear/
borrow helpers are normalized for the existing lifecycle walker. No function body,
native status or pointer is rewritten. Separate capture, envelope and destructor
projections compose here; keyed worker computation remains unqualified.
"""
import re
import sys
from types import SimpleNamespace

import legacy_hmac_engine_codegen as shared
import legacy_hmac_timing_runner as runner
import legacy_hmac_hosted_launch as launch

sys.path.append(str(shared.SHARED))
import legacy_hmac_hosted_capture as capture
import legacy_hmac_hosted_buffers as buffers
import legacy_hmac_hosted_types as capture_types
import legacy_hmac_hosted_envelope as envelope

model = shared.load('hmac_hosted_lifecycle', 'legacy_hosted_lifecycle_model')
contracts = shared.load('hmac_hosted_contracts')
flow, syntax, require = model.common, model.syntax, model.require


def profile(target):
    _, resource = original_profile(target)
    return 'brynja_legacy_hmac_std::' + ('macos_resident' if target == 'aarch64-apple-darwin'
                                       else 'strict_execution'), resource


# The isolated model keeps modern HMAC's checker and profile untouched.
original_profile = model.profile
model.profile = profile


def lifecycle_call(line):
    call = syntax.call(line)
    pure = {'llvm.umin.i64': 'i64', 'llvm.uadd.with.overflow.i128': 'i128'}
    if call and call[0] in pure:
        dtype = pure[call[0]]
        require('invoke ' not in line and len(call[1]) == 2
                and all(re.fullmatch(dtype + r'(?: noundef)?(?: range\(' + dtype + r' -?\d+, -?\d+\))? (?:%[-\w.]+|\d+)', arg)
                        for arg in call[1]),
                'unreviewed host integer intrinsic')
        # Pure integer arithmetic, not a call into external code. The shared
        # walker still rejects this instruction while a worker is unjoined.
        return None
    return call


model.syntax = SimpleNamespace(call=lifecycle_call, operand=syntax.operand)


def graph(metadata, fixture, hosted_manifest=None):
    edges = {
        'brynja-core': set(), 'brynja-hash-core': set(), 'brynja-crypto-cpu': set(),
        'brynja-crypto-cpu-std': {'brynja-core', 'brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-hash-sha3'},
        'brynja-hash-sha2': {'brynja-core', 'brynja-crypto-cpu', 'brynja-hash-core'},
        'brynja-hash-sha3': {'brynja-core', 'brynja-hash-core'},
        'brynja-legacy-sha1': {'brynja-core', 'brynja-hash-core'},
        'brynja-legacy-md5': {'brynja-core', 'brynja-hash-core'},
        'brynja-legacy-hmac': {'brynja-core', 'brynja-legacy-sha1', 'brynja-legacy-md5'},
        'brynja-legacy-hmac-std': {'brynja-core', 'brynja-crypto-cpu-std', 'brynja-legacy-hmac'},
        'brynja-legacy-hmac-hosted-cleanup': {'brynja-legacy-hmac-std'},
    }
    expected = set(edges)
    packages, nodes = metadata['packages'], metadata['resolve']['nodes']
    require(len(packages) == len(nodes) == len(expected) and {p['name'] for p in packages} == expected
            and {p['id'] for p in packages} == {n['id'] for n in nodes}, 'legacy hosted fixture graph changed')
    require(all(p['source'] is None for p in packages), 'nonlocal legacy hosted dependency')
    require(all('runtime-execution' not in n['features'] for n in nodes), 'runtime contamination of static fixture')
    identities = {p['id']: p['name'] for p in packages}
    for package in packages:
        path = fixture if package['name'] == 'brynja-legacy-hmac-hosted-cleanup' else (
            runner.ROOT / 'crates' / package['name'] / 'Cargo.toml')
        if hosted_manifest is not None and package['name'] == 'brynja-legacy-hmac-std':
            path = hosted_manifest  # Explicit private compiled-mutant source only; no CLI override.
        require(package['manifest_path'] == str(path.resolve()), 'legacy hosted dependency path substitution')
        require(not any('custom-build' in target['kind'] for target in package['targets']),
                'legacy hosted build-script contamination')
    for node in nodes:
        require(set(node['dependencies']) <= set(identities), 'unknown legacy hosted dependency edge')
        require({identities[item] for item in node['dependencies']} == edges[identities[node['id']]],
                'legacy hosted dependency edge changed')
        if identities[node['id']] == 'brynja-legacy-hmac-std':
            require({'strict-sha1-acceleration', 'macos-resident-sha1-acceleration', 'strict-md5-batch',
                     'macos-resident-md5-batch'} <= set(node['features']) and 'default' not in node['features'],
                    'legacy hosted static feature selection changed')


def dispatch(signature, body, names, expected, identity, operation, direct=False):
    selected = [(label, index, call) for label, lines in flow.blocks(body).items()
                for index, line in enumerate(lines) if (call := syntax.call(line)) and names.get(call[0]) == expected]
    require(len(selected) == 1, 'legacy consumer lost typed dispatch: ' + expected)
    label, index, (symbol, args) = selected[0]
    first = next(iter(flow.blocks(body).items()))
    require(label == first[0] and not any(line.startswith(('br ', 'switch ', 'ret '))
                                        or 'invoke ' in line for line in first[1][:index]),
            'legacy consumer can bypass dispatch')
    token = lambda argument: argument.split()[-1]
    formals = [token(arg) for arg in syntax.parameters(signature)]
    if direct:
        wanted = formals
    else:
        if operation == 'compute':
            formals = formals[1:]  # Return object is built after execute.
        if operation == 'verify':
            wanted = formals
        elif identity == 'md5_compiled':
            wanted = [*formals[:2], 'null', formals[-1]]
        else:
            require(token(args[3]) in ('undef', 'poison'), 'absent candidate gained a length')
            wanted = [*formals[:2], 'null', token(args[3]), formals[-1]]
    require([token(arg) for arg in args] == wanted, 'legacy dispatch argument/mode provenance changed')
    return symbol


def validate(artifacts, target):
    contracts.validate()
    capture_types.validate()
    owner, resource = profile(target)
    populations = {}
    for package, llvm in artifacts.items():
        definitions, aliases = flow.definitions_and_aliases(llvm)
        symbols = {name.strip('"') for name in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)}
        names = model.demangle(symbols)
        populations[package] = definitions, aliases, names
    fixture = populations['brynja-legacy-hmac-hosted-cleanup']
    leaf = populations['brynja-legacy-hmac-std']
    destructor = '<' + owner + '::Buffers as core::ops::drop::Drop>::drop'
    selected = [symbol for symbol in (*leaf[0], *leaf[1]) if leaf[2][symbol] == destructor]
    require(len(selected) == 1, 'missing/ambiguous legacy buffer destructor')
    buffers.check(*flow.resolve(selected[0], *leaf[:2]), leaf[2], target)
    expected = {
        'sha1': '<' + owner + '::Session<brynja_legacy_hmac::algorithms::Sha1>>::execute',
        'md5': '<' + owner + '::Session<brynja_legacy_hmac::algorithms::Md5>>::execute',
        'sha1_compiled': '<' + owner + '::sha1_compiled::Sha1CompiledSession>::execute',
        'md5_compiled': '<' + owner + '::md5_compiled::Md5BatchSession>::execute',
    }
    checked = {}
    for identity, executor_name in expected.items():
        for operation in ('compute', 'verify'):
            entry = 'brynja_legacy_hmac_hosted_cleanup::' + identity + '::' + operation
            entries = [symbol for symbol in (*fixture[0], *fixture[1]) if fixture[2][symbol] == entry]
            require(len(entries) == 1, 'missing/ambiguous legacy host consumer: ' + entry)
            signature, body = flow.resolve(entries[0], *fixture[:2])
            if identity.endswith('_compiled'):
                public_name = executor_name.removesuffix('execute') + operation
                public = dispatch(signature, body, fixture[2], public_name, identity, operation, direct=True)
                signature, body = flow.resolve(public, *leaf[:2])
                selected = dispatch(signature, body, leaf[2], executor_name, identity, operation)
            else:
                selected = dispatch(signature, body, fixture[2], executor_name, identity, operation)
            if identity in checked:
                require(checked[identity][0] == selected, 'compute/verify select different executors')
                continue
            population = fixture if selected in fixture[0] or selected in fixture[1] else leaf
            definitions, aliases, names = population
            signature, host = flow.resolve(selected, definitions, aliases)
            launch.Launch(signature, host, names, target, identity, resource)
            capture.check(signature, host, names, target, identity)
            normalized = dict(names)
            for symbol, name in names.items():
                if identity == 'md5_compiled' and name == owner + '::md5_compiled::types::validate':
                    normalized[symbol] = owner + '::types::validate'
                if name == '<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::clear':
                    normalized[symbol] = '<brynja_crypto_cpu_std::protected_memory::ProtectedBytes>::clear'
                if name == '<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::as_bytes_mut':
                    normalized[symbol] = '<' + resource + '::Mapping>::bytes_mut'
            worker = model.check_host(host, normalized, definitions, target)
            closure = executor_name + '::{closure#0}'
            require(names[worker] in (resource + '::thread::enter::<' + closure + '>',
                                      resource + '::thread::enter<' + closure + '>'),
                    'legacy executor launches another closure')
            envelope.check(*flow.resolve(worker, definitions, aliases), names, identity)
            checked[identity] = selected, worker, population, host
    require(len(checked) == 4 and len({item[1] for item in checked.values()}) == 4,
            'legacy host/worker population collapsed')
    return checked
