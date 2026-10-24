"""Every normal success return must have all independently bound report fields.

Overapproximate branches, including invoke unwind edges. Track only writes to
the nonescaping noalias return object; no branch is assumed successful. The
consumer's success/error semantics and output-owner lifetime remain separate.
"""
import re

import legacy_hmac_md5_return_header as header

r, output = header.r, header.output
require, Bits = r.require, r.Bits


def classify(check, base, niche):
    writes = output.writes(check.body)
    successes, errors = [], set()
    for site, offset, size, dtype, name in writes:
        if not output.overlap(offset, size, niche, 1):
            continue
        if offset == niche and dtype == 'i8' and name == '2':
            errors.add(site)
        else:
            require((niche == base + 80 and offset == niche and dtype == 'i8') or
                    (niche == 0 and offset == 0 and dtype == 'i64'), 'unbound success-discriminant write')
            successes.append((site, dtype, name))
    require(len(successes) == 1 and errors, 'normal-return variant writers changed')
    site, dtype, name = successes[0]
    r.phases.dominates(check.graph, (check.stop, -1), site)

    for backend in (0, 1):
        for mask in range(256):
            def compare(state):
                actual = state.value(name, dtype)
                expected = Bits.integer(backend if niche else mask & 1, 8)
                require(Bits(actual.data[:8]) == expected, 'return success niche is not selected backend/activity')
            check.run_report(mask, backend, on_entry=compare)
    return writes, site, errors


def walk(check, base, niche):
    params = r.syntax.parameters(check.signature)
    require('noalias' in params[0] and 'sret(' in params[0] and r.syntax.operand(params[0]) == '%_0',
            'return object lost exclusive sret contract')
    writes, success, errors = classify(check, base, niche)
    require(all(0 <= offset <= base + 88 - size for _, offset, size, _, _ in writes),
            'return object write exceeds ABI-bound extent')
    by_site = {site: (offset, size) for site, offset, size, _, _ in writes}
    require(len(by_site) == len(writes), 'ambiguous return-object writer')
    graph = check.graph
    wanted = (1 << 81) - 1  # width + three work reports + backend; excludes padding.
    pending, seen = [(next(iter(graph)), 0, 'unset', 0)], set()
    witnessed = set()
    while pending:
        label, index, kind, covered = pending.pop()
        state = label, index, kind, covered
        if state in seen:
            continue
        seen.add(state)
        require(len(seen) < 50000, 'normal-return report path bound exceeded')
        require(label in graph, 'unknown normal-return report edge')
        lines = graph[label]
        while index < len(lines):
            site, line = (label, index), lines[index]
            if site in errors:
                kind, covered = 'error', 0
            elif site == success:
                kind = 'success'
            if site in by_site and site not in errors:
                offset, size = by_site[site]
                for byte in output.overlap(offset, size, base, 81):
                    covered |= 1 << (byte - base)
            if line == 'ret void':
                require(kind != 'unset', 'normal return lacks a bound result variant')
                require(kind != 'success' or covered == wanted, 'normal success return lacks complete report fields')
                witnessed.add(kind)
                break
            if line.startswith(('ret ', 'resume ', 'unreachable')):
                require(not line.startswith('ret '), 'unexpected normal-return representation')
                break
            if line.startswith(('br ', 'switch ')) or 'invoke ' in line:
                tail = '\n'.join(lines[index:])
                edges = re.findall('label %' + r.flow.LABEL, tail)
                require(edges, 'return path lacks successors')
                pending.extend((child, 0, kind, covered) for child in edges)
                break
            index += 1
        else:
            require(False, 'normal-return block lacks terminator')
    require(witnessed == {'success', 'error'}, 'normal-return coverage is vacuous')
    return success, errors, seen


def validate(fixture, llvm):
    offsets = header.probes(fixture)
    definitions, aliases = r.flow.definitions_and_aliases(llvm)
    results = []
    for operation, (base, niche) in offsets.items():
        signature, body = r.phases.rows.method(definitions, aliases, operation)[1]
        check = r.inner.Check(signature, body, llvm)
        check.signature = signature
        results.append(walk(check, base, niche))
    return results
