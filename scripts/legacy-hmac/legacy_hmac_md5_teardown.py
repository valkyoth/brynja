"""Post-consumer success is a closed, non-refilling teardown path.

Core clear/region Drop and Md5Owner Drop are source-pinned nonthrowing premises
for valid Rust regions. The emitted Workspace destructor is separately walked.
Thus only normal edges of those specific cleanup invokes are feasible here;
this is not a blanket assumption that arbitrary Drop implementations cannot
unwind. Earlier consumer failures/unwinds remain separate checks. No fatal,
instrumentation, caller-frame or register-erasure claim is made.
"""
import re

import legacy_hmac_md5_consumer_return as consumer
import legacy_hmac_md5_pad_model as model

r = consumer.r
flow, syntax, require, VALUE = r.flow, r.syntax, r.require, r.VALUE
contracts = r.phases.rows.contracts


def prepare(fixture, llvm):
    definitions, aliases = flow.definitions_and_aliases(llvm)
    copy_ok = r.n.pads.probes(fixture)
    result = []
    for operation, (base, niche) in consumer.header.probes(fixture).items():
        signature, body = r.phases.rows.method(definitions, aliases, operation)[1]
        check = r.inner.Check(signature, body, llvm)
        check.signature = signature
        fields = consumer.fields(check, base, niche)
        site = consumer.gate(check, operation, fields, copy_ok)
        if operation == 'authenticate_secret':
            consumer.region_transport(check, site, fields)
        normal, _ = r.n.results.continuation(check.graph, site)
        if operation == 'verify':
            start = normal
        else:
            edges = re.findall('label %' + flow.LABEL, check.graph[normal[0]][-1])
            require(len(edges) == 2, 'teardown consumer admission lost its two edges')
            start = (edges[0 if operation == 'authenticate' else 1], 0)
        result.append((check, operation, fields, site, start))
    return result


def preserved_region(check, fields):
    """The returned region pointer/extent may only flow to their return slots."""
    for offset in (8, 16):
        dtype, name, site = fields[offset]
        uses = []
        for label, lines in check.graph.items():
            for index, line in enumerate(lines):
                definition = re.match(rf'({VALUE}) = ', line)
                if definition and definition[1] == name:
                    continue
                if name in re.findall(VALUE, line):
                    uses.append((label, index))
        require(uses == [site] and dtype == ('ptr' if offset == 8 else 'i64'),
                'returned region pointer/extent escapes or is reused before transfer')


def walk(check, operation, fields, consumer_site, start, definitions, aliases, panic, llvm):
    graph, allocs = check.graph, check.allocs
    output = syntax.operand(syntax.parameters(check.signature)[0])
    pointers = syntax.pointers(check.body, (*allocs, output))
    rows = {r.phases.owner(allocs, name, size): size for name, size in
            (('truncated', 128), ('final_tags', 128), ('inner', 128), ('pad', 512))}
    owners = {r.phases.owner(allocs, name, 16) for name in ('tags', 'inner_owner')}
    workspace = r.phases.owner(allocs, 'workspace', 912)
    expected = {('clear', root) for root in rows} | {('drop', root) for root in owners} | {('workspace', workspace)}
    if operation == 'authenticate_secret':
        preserved_region(check, fields)
    # These transfers and all output stores have independent provenance checks.
    report = consumer.storage.Check(check.body, {'authenticate': 24, 'authenticate_secret': 32, 'verify': 8}[operation])
    copies = {item[0] for item in report.chain}
    writes = {item[0] for item in consumer.output.writes(check.body)}
    pending = [(start[0], start[1], frozenset(), frozenset(), frozenset(), frozenset())]
    witnessed, qualified = set(), set()
    while pending:
        label, index, cleaned, dead, committed, trail = pending.pop()
        require(label not in trail and len(trail) < 40, 'cyclic/oversized success teardown')
        trail = trail | {label}
        lines = graph[label]
        while index < len(lines):
            site, line = (label, index), lines[index]
            call = syntax.call(line)
            definition = re.fullmatch(rf'({VALUE}) = (.*)', line)
            if call:
                symbol, args = call
                if symbol == 'llvm.lifetime.end.p0':
                    root = syntax.operand(args[-1])
                    require(root in allocs and root not in dead and len(args) in (1, 2)
                            and (len(args) == 1 or args[0] == 'i64 ' + str(allocs[root])), 'teardown lifetime changed')
                    obligation = ('clear', root) if root in rows else ('drop', root) if root in owners else (
                        ('workspace', root) if root == workspace else None)
                    require(obligation is None or obligation in cleaned, 'teardown expires uncleared storage')
                    dead = dead | {root}
                elif symbol == 'llvm.experimental.noalias.scope.decl':
                    pass
                elif symbol == 'llvm.memcpy.p0.p0.i64':
                    require(site in copies, 'success teardown gained an unbound copy')
                    require(all(pointers.get(syntax.operand(arg), (None,))[0] not in dead for arg in args[:2]),
                            'success teardown copies expired storage')
                else:
                    root = syntax.operand(args[0]) if args else None
                    require(root in allocs and root not in dead, 'teardown callee receives nonlocal/expired storage')
                    if model.primitive(symbol, 'clear_owned_region'):
                        require(root in rows and len(args) == 2 and args[1] == 'i64 noundef ' + str(rows[root]),
                                'teardown clear changed region/extent')
                        event = 'clear', root
                    elif contracts.region_drop(symbol):
                        require('17OwnedSecretRegion' in symbol or '..OwnedSecretRegion' in symbol,
                                'success teardown destroys an initialization instead of an internal region')
                        require(root in owners and len(args) == 1, 'success teardown destroys another region owner')
                        event = 'drop', root
                    else:
                        require(contracts.workspace_drop(symbol) and root == workspace and len(args) == 1,
                                'success teardown gained a callback/fallible operation')
                        if symbol not in qualified:
                            contracts.workspace(symbol, definitions, aliases, panic, llvm)
                            qualified.add(symbol)
                        event = 'workspace', root
                    require(event not in cleaned, 'success teardown repeats destruction')
                    cleaned = cleaned | {event}
                if 'invoke ' in line:
                    normal, _ = r.n.results.continuation(graph, (label, index, symbol, args))
                    require(normal[1] == 0, 'teardown invoke continuation changed')
                    pending.append((normal[0], 0, cleaned, dead, committed, trail))
                    break
            elif definition:
                name, expr = definition.groups()
                gep = re.fullmatch(r.n.pads.descriptors.GEP, line)
                load = re.fullmatch(rf'load (ptr|i64), ptr ({VALUE}), align 8(?:, !.*)?', expr)
                if gep:
                    root, offset = pointers.get(name, (None, -1))
                    require((root == output and 0 <= offset < (120 if operation == 'authenticate_secret' else 112 if operation == 'authenticate' else 96))
                            or (root in allocs and root not in dead and 0 <= offset < allocs[root]),
                            'teardown pointer leaves live local/return storage')
                elif load:
                    root, offset = pointers.get(load[2], (None, -1))
                    require(operation == 'authenticate_secret' and root == syntax.operand(consumer_site[3][0])
                            and root not in dead and ((load[1], offset, name) in
                            (('ptr', 8, fields[8][1]), ('i64', 16, fields[16][1]))), 'teardown reads unbound storage')
                elif re.fullmatch(rf'trunc nuw nsw i64 {VALUE} to i8|select i1 {VALUE}, (i8|i64) 4, \1 8', expr):
                    base = {'authenticate': 24, 'authenticate_secret': 32, 'verify': 8}[operation]
                    require(any(offset == base and dtype in ('i8', 'i64') and value == name
                                for _, offset, _, dtype, value in consumer.output.writes(check.body)),
                            'teardown expression is not the independently bound report width')
                else:
                    require(False, 'unreviewed success teardown expression: ' + expr)
            elif line.startswith('store '):
                require(site in writes, 'success teardown writes outside the bound returned object')
                committed = committed | {site}
            elif line == 'ret void':
                require(cleaned == expected and {field[2] for field in fields.values()} <= committed,
                        'success return lost cleanup or returned ownership fields')
                witnessed.add(label)
                break
            elif line.startswith('br label %'):
                target = re.fullmatch('br label %' + flow.LABEL, line)
                require(target, 'unparsed teardown successor')
                pending.append((target[1], 0, cleaned, dead, committed, trail))
                break
            else:
                require(False, 'success teardown is not a nonthrowing return path: ' + line)
            index += 1
        else:
            require(False, 'success teardown lacks a terminator')
    require(witnessed, 'success teardown check is vacuous')
    return witnessed


def validate(fixture, llvm, panic):
    contracts.validate()
    r.n.results.fence.validate_source()
    definitions, aliases = flow.definitions_and_aliases(llvm)
    checks = prepare(fixture, llvm)
    for check, operation, fields, site, start in checks:
        walk(check, operation, fields, site, start, definitions, aliases, panic, llvm)
    return checks
