"""Qualify compiled-out workers as rejection only, never as authority execution."""
import re

import legacy_hmac_hosted_authority as authority
from legacy_hmac_md5_phases import dominates

flow, syntax, require, V = authority.flow, authority.syntax, authority.require, authority.V


def check(body, envelope, identity):
    graph = flow.blocks(body)
    definitions = {m[1]: (m[2], (label, i)) for label, lines in graph.items()
                   for i, line in enumerate(lines) if (m := re.match('(' + V + ') = (.*)', line))}
    allowed_loads = {0} if identity == 'sha1_compiled' else {8, 24, 32, 80}
    require(set(envelope['loads']) <= allowed_loads, 'compiled-out worker reads secret/extra captures')
    loads = {site for site, _ in envelope['loads'].values()}
    stores = {envelope['take'], envelope['completed'], *(site for site, _ in envelope['result_stores'])}
    for site, offset in envelope['result_stores']:
        if offset:
            require(re.match(r'store i8 4, ptr ', graph[site[0]][site[1]]), 'compiled-out error payload changed')
    for label, lines in graph.items():
        for i, line in enumerate(lines):
            call = syntax.call(line)
            if call:
                require(call[0] in ('llvm.assume', 'llvm.experimental.noalias.scope.decl'),
                        'compiled-out worker executes an unexpected call')
            require(not re.search(r'\b(?:invoke|atomicrmw|cmpxchg|alloca)\b', line),
                    'compiled-out worker gained memory/effect path')
            if re.search(r'\bload\b', line):
                require((label, i) in loads, 'compiled-out worker reads outside launch metadata')
            if line.startswith('store '):
                require((label, i) in stores, 'compiled-out worker writes outside status envelope: ' + line)
    site = envelope['result']
    store = re.match(r'store i(8|16) (' + V + r'|-?\d+), ptr ', graph[site[0]][site[1]])
    require(store, 'compiled-out worker status shape changed')
    def values(value, trail=()):
        if re.fullmatch(r'-?\d+', value):
            return {int(value)}
        require(value in definitions and value not in trail, 'unknown compiled-out result')
        rhs, point = definitions[value]
        dominates(graph, point, site)
        selected = re.fullmatch(r'select i1 ' + V + r', i(8|16) (' + V + r'|-?\d+), i\1 (' + V + r'|-?\d+)', rhs)
        require(selected, 'unreviewed compiled-out result expression')
        return values(selected[2], (*trail, value)) | values(selected[3], (*trail, value))
    expected = {7, 8} if store[1] == '8' else {1031, 1032}
    require(values(store[2]) <= expected, 'compiled-out worker can return success')
