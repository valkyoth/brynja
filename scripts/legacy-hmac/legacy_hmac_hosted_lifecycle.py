"""Bind legacy host routes to the shared, source-reviewed thread lifecycle.

Presentation names of exact reviewed callees are adapted only for shared walker
selection (the MD5 validator, resident helpers and streaming terminal/update
selectors). No function body, native status or pointer is rewritten. Capture, envelope, destructor, authority
and selection-input projections compose here with compiled keyed admission,
scalar construction and retained dispatch. Streaming input/tail and output-owner
provenance compose here with scalar and accelerated SHA-1 checkpoints/callees,
including inlined temporary streams and worker Result status transport. MD5's
borrowed health selectors, three checkpoint positions and rejection payload
transport also compose here. Typed MD5 report predicates, captured backend,
eight-slot active count and report rejection transport are checked separately.
Typed consumer Result projections also bind report-byte transfers and admission.
Typed lane layouts bind the eight input/key/BitString transfers and slot chain.
The shared control binds budget, callback context and both actual vtable targets.
Candidate mode and the typed public decision bind through final Result storage.
MD5 tag-output copies bind each active source lane to its matching output row
through normal-return copy-error handling and owned-region Drop admission.
Pending Result ownership and post-transfer normal/unwind destruction/lifetime
paths compose with the source-bound nonthrowing core clearing premise. Joined
host output/decision/quarantine transactions and armed pre-entry rejections now
compose too. Ordinary output loan construction/exposure/declassification/drop
now compose with those transactions. MD5 batch loan factories, active-lane
views, declassification and consuming moves/clearing also compose. Bounded
public-request admission executes actual inlined/outlined validation before
worker-storage access, including cancellation, clearing and quarantine order.
Reconciliation binds these artifacts through the exact callback, result slot,
completion flags and borrowed-local lifetimes. Ordinary setup-error returns and
public verification decision/error conversion also compose. This is a bounded
compiler projection chain, not whole-worker erasure or native qualification.
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
import legacy_hmac_hosted_authority as authority
import legacy_hmac_hosted_constructor as constructor
import legacy_hmac_hosted_unavailable as unavailable
import legacy_hmac_hosted_backend as backend
import legacy_hmac_hosted_keyed as keyed
import legacy_hmac_hosted_storage as storage
import legacy_hmac_hosted_retained as retained
import legacy_hmac_hosted_scalar as scalar
import legacy_hmac_hosted_input as input_flow
import legacy_hmac_hosted_output as output
import legacy_hmac_hosted_checkpoints as checkpoints
import legacy_hmac_hosted_checkpoint_flow as checkpoint_flow
import legacy_hmac_hosted_checkpoint_inline as checkpoint_inline
import legacy_hmac_hosted_checkpoint_boundaries as checkpoint_boundaries
import legacy_hmac_hosted_md5_checkpoint as md5_checkpoint
import legacy_hmac_hosted_md5_health as md5_health
import legacy_hmac_hosted_md5_boundaries as md5_boundaries
import legacy_hmac_hosted_md5_report_layout as md5_report_layout
import legacy_hmac_hosted_md5_report_logic as md5_report_logic
import legacy_hmac_hosted_md5_report_caller as md5_report_caller
import legacy_hmac_hosted_md5_result_layout as md5_result_layout
import legacy_hmac_hosted_md5_result_transport as md5_result_transport
import legacy_hmac_hosted_md5_lane_layout as md5_lane_layout
import legacy_hmac_hosted_md5_lanes as md5_lanes
import legacy_hmac_hosted_md5_control as md5_control
import legacy_hmac_hosted_md5_decision as md5_decision
import legacy_hmac_hosted_md5_tag_copy as md5_tag_copy
import legacy_hmac_hosted_md5_tag_cleanup as md5_tag_cleanup
import legacy_hmac_hosted_md5_result_cleanup as md5_result_cleanup
import legacy_hmac_hosted_transaction as transaction
import legacy_hmac_hosted_loans as loans
import legacy_hmac_hosted_batch_loans as batch_loans
import legacy_hmac_hosted_batch_creation as batch_creation
import legacy_hmac_hosted_prearm as prearm
import legacy_hmac_hosted_prearm_layout as prearm_layout
import legacy_hmac_hosted_reconcile as reconcile
import legacy_hmac_hosted_verify as verification

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


def graph(metadata, fixture, hosted_manifest=None, legacy_manifest=None):
    edges = {
        'brynja-core': set(), 'brynja-hash-core': set(), 'brynja-crypto-cpu': set(),
        'brynja-crypto-cpu-std': {'brynja-core', 'brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-hash-sha3'},
        'brynja-hash-sha2': {'brynja-core', 'brynja-crypto-cpu', 'brynja-hash-core'},
        'brynja-hash-sha3': {'brynja-core', 'brynja-hash-core'},
        'brynja-legacy-sha1': {'brynja-core', 'brynja-hash-core'},
        'brynja-legacy-md5': {'brynja-core', 'brynja-hash-core'},
        'brynja-legacy-hmac': {'brynja-core', 'brynja-legacy-sha1', 'brynja-legacy-md5'},
        'brynja-legacy-hmac-std': {'brynja-core', 'brynja-crypto-cpu-std', 'brynja-legacy-hmac'},
        'brynja-legacy-hmac-hosted-cleanup': {'brynja-legacy-hmac-std', 'brynja-core',
                                            'brynja-legacy-sha1', 'brynja-legacy-md5', 'brynja-legacy-hmac'},
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
        if legacy_manifest is not None and package['name'] == 'brynja-legacy-hmac':
            path = legacy_manifest  # Same exact-path test-only binding for constructor mutants.
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


def validate(artifacts, target, panic, reconciled=None):
    require(reconciled is None or isinstance(reconciled, dict) and not reconciled,
            'reconciliation output must be a fresh empty dictionary')
    require(panic in ('abort', 'unwind'), 'explicit legacy hosted panic profile required')
    contracts.validate()
    capture_types.validate()
    authority.modes(runner.ROOT)
    owner, resource = profile(target)
    populations = {}
    compilers = set()
    for package, llvm in artifacts.items():
        versions = re.findall(r'!"rustc version ([\d.]+) ', llvm)
        require(len(versions) == 1 and versions[0] in ('1.90.0', '1.99.1'), 'unreviewed legacy hosted compiler')
        compilers.add(versions[0])
        definitions, aliases = flow.definitions_and_aliases(llvm)
        symbols = {name.strip('"') for name in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)}
        names = model.demangle(symbols)
        populations[package] = definitions, aliases, names
    require(len(compilers) == 1, 'mixed legacy hosted compilers')
    compiler = compilers.pop()
    fixture = populations['brynja-legacy-hmac-hosted-cleanup']
    loans.validate(fixture, target, compiler, panic)
    prearm_layout.validate(fixture)
    verification.typed(fixture, compiler)
    initials = scalar.normalization.contracts.validate(fixture)
    checkpoint_flow.probes(fixture)
    md5_report_layout.validate(fixture)
    md5_result_layout.validate(fixture)
    md5_lane_layout.validate(fixture)
    md5_control.typed(fixture)
    md5_decision.typed(fixture, compiler)
    md5_tag_copy.typed(fixture, compiler)
    leaf = populations['brynja-legacy-hmac-std']
    batch_loans.validate(fixture, leaf, target, compiler, panic)
    checkpoints.validate_callees(leaf, target, compiler)
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
    checked, summaries = {}, {}
    for identity, executor_name in expected.items():
        for operation in ('compute', 'verify'):
            entry = 'brynja_legacy_hmac_hosted_cleanup::' + identity + '::' + operation
            entries = [symbol for symbol in (*fixture[0], *fixture[1]) if fixture[2][symbol] == entry]
            require(len(entries) == 1, 'missing/ambiguous legacy host consumer: ' + entry)
            signature, body = flow.resolve(entries[0], *fixture[:2])
            if identity.endswith('_compiled'):
                public_name = executor_name.removesuffix('execute') + operation
                public = dispatch(signature, body, fixture[2], public_name, identity, operation, direct=True)
                if operation == 'verify':
                    verification.check(signature, body, fixture[2], target, compiler, identity, public_name, forwarding=True)
                signature, body = flow.resolve(public, *leaf[:2])
                selected = dispatch(signature, body, leaf[2], executor_name, identity, operation)
            else:
                selected = dispatch(signature, body, fixture[2], executor_name, identity, operation)
            if operation == 'verify':
                verification.check(signature, body, leaf[2] if identity.endswith('_compiled') else fixture[2],
                                   target, compiler, identity, executor_name)
            if operation == 'compute' and identity != 'md5_compiled':
                loans.creation(signature, body, leaf[2] if identity.endswith('_compiled') else fixture[2],
                               target, compiler, identity, executor_name)
            if operation == 'compute' and identity == 'md5_compiled':
                batch_creation.creation(signature, body, leaf[2], target, compiler, executor_name)
            if identity in checked:
                require(checked[identity][0] == selected, 'compute/verify select different executors')
                continue
            population = fixture if selected in fixture[0] or selected in fixture[1] else leaf
            definitions, aliases, names = population
            signature, host = flow.resolve(selected, definitions, aliases)
            prefix = prearm.check(signature, host, names, leaf, target, identity, compiler)
            native = launch.Launch(signature, host, names, target, identity, resource)
            captured = capture.check(signature, host, names, target, identity)
            joined = transaction.check(captured, compiler, owner, resource)
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
            worker_signature, worker_body = flow.resolve(worker, definitions, aliases)
            envelope_result = envelope.check(worker_signature, worker_body, names, identity)
            summary = reconcile.check(prefix, native, captured, joined, worker, worker_signature,
                                      worker_body, envelope_result)
            if identity.endswith('_compiled'):
                worker_body = flow.resolve(worker, definitions, aliases)[1]
                if any('::for_compiled_target' in names.get(call[0], '') for line in worker_body.splitlines()
                       if (call := syntax.call(line))):
                    transfer = authority.check(worker_body, names, compiler, identity)
                    constructor.check(transfer, envelope_result)
                    backend.check(transfer, envelope_result)
                    keyed_state = keyed.check(worker_body, names, compiler, identity)
                    # retained.check includes storage validation for both
                    # identities; do not repeat the same graph traversal.
                    retained.check(keyed_state, definitions, aliases, panic)
                    if identity == 'sha1_compiled':
                        callee = owner + '::sha1_compiled::worker::checkpoint'
                        selected_callees = [s for s in (*leaf[0], *leaf[1]) if leaf[2].get(s) == callee]
                        require(len(selected_callees) == 1, 'accelerated SHA-1 checkpoint callee missing/ambiguous')
                        checkpoint_flow.validate(*flow.resolve(selected_callees[0], *leaf[:2]), leaf[2], compiler)
                        arguments = flow.resolve(worker, definitions, aliases)[0]
                        incoming = input_flow.check(keyed_state, arguments, envelope_result, panic, compiler)
                        outgoing = output.check(keyed_state, arguments, panic)
                        records, _ = checkpoint_inline.check(keyed_state, incoming, transfer, target)
                        checkpoint_boundaries.Boundaries(keyed_state, incoming, outgoing, transfer,
                                                         records, target, compiler).check()
                    else:
                        callee = owner + '::md5_compiled::worker::checkpoint'
                        selected_callees = [s for s in (*leaf[0], *leaf[1]) if leaf[2].get(s) == callee]
                        require(len(selected_callees) == 1, 'MD5 checkpoint callee missing/ambiguous')
                        md5_checkpoint.validate(*flow.resolve(selected_callees[0], *leaf[:2]), leaf[2], compiler)
                        health_result = md5_health.check(keyed_state, transfer, envelope_result, compiler)
                        boundaries = md5_boundaries.check(keyed_state, transfer, envelope_result, compiler, target, health_result)
                        report = owner + '::md5_compiled::worker::report'
                        selected_reports = [s for s in (*leaf[0], *leaf[1]) if leaf[2].get(s) == report]
                        require(len(selected_reports) == 1, 'MD5 report callee missing/ambiguous')
                        md5_report_logic.validate(*flow.resolve(selected_reports[0], *leaf[:2]), compiler)
                        md5_report_caller.check(keyed_state, transfer, envelope_result, compiler, target)
                        transports = md5_result_transport.check(keyed_state, health_result, target)
                        md5_lanes.check(keyed_state, transfer, envelope_result, health_result)
                        md5_control.check(keyed_state, envelope_result, artifacts['brynja-legacy-hmac-std'], leaf, target)
                        md5_decision.check(keyed_state, envelope_result, boundaries, transports, compiler)
                        copies = md5_tag_copy.check(keyed_state, envelope_result, boundaries, transports, compiler)
                        post = md5_tag_cleanup.check(copies, panic)
                        md5_result_cleanup.check(copies, post, health_result, panic)
                else:
                    unavailable.check(worker_body, envelope_result, identity)
            else:
                arguments, worker_body = flow.resolve(worker, definitions, aliases)
                state, _ = scalar.check(worker_body, names, compiler, identity, envelope_result,
                                        definitions, aliases, panic, initials[identity])
                incoming = input_flow.check(state, arguments, envelope_result, panic, compiler)
                outgoing = output.check(state, arguments, panic)
                checkpoints.Checkpoints(incoming, outgoing, target, compiler).check()
            checked[identity] = selected, worker, population, host
            summaries[identity] = summary
    require(len(checked) == 4 and len({item[1] for item in checked.values()}) == 4,
            'legacy host/worker population collapsed')
    if reconciled is not None:
        reconciled.update(summaries)
    return checked
