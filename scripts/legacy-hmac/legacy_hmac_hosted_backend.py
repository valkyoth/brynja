"""Exclude mismatched/absent worker backends before keyed selection.

Exhaust the two valid captured backend discriminants and the owner's None
discriminant. This proves the emitted comparison, not platform CPU suitability.
"""
import re

import legacy_hmac_hosted_authority as authority
from legacy_hmac_hosted_constructor import read_capture

values = authority.shared.load('hmac_hosted_transaction_values')
require, syntax, V = authority.require, authority.syntax, authority.V


def check(t, envelope):
    loads = envelope['loads']
    if t.identity == 'sha1_compiled':
        captured = [read_capture(t, loads, 8, 'i8')]
        reports = [(symbol, site) for symbol, _, site in t.calls
                   if t.names.get(symbol) == authority.SHA1 + '::report']
        require(len(reports) == 1, 'worker backend report population')
        report = re.match('(' + V + ') = ', t.graph[reports[0][1][0]][reports[0][1][1]])
        require(report, 'worker backend report return changed')
        owner = [(name, site) for name, (rhs, site) in t.defs.items()
                 if rhs == 'extractvalue { i1, i8 } ' + report[1] + ', 1']
        if owner:
            require(t.before(reports[0][1], owner[0][1]), 'backend extraction before report')
    else:
        require(80 in loads, 'captured MD5 backend missing')
        captured = [(loads[80][1], loads[80][0])]
        owner = [(name, site) for name, (rhs, site) in t.defs.items()
                 if (load := re.match(r'load i8, ptr (' + V + '),', rhs))
                 and t.pointer(load[1], site) == (t.owner, 9)]
    require(len(captured) == len(owner) == 1, 'missing/ambiguous worker backend values')
    captured, owner = captured[0], owner[0]
    found = []
    for label, lines in t.graph.items():
        branch = re.fullmatch(r'br i1 (' + V + '), label %' + authority.flow.LABEL
                              + ', label %' + authority.flow.LABEL, lines[-1])
        if not branch:
            continue
        site = label, len(lines) - 1
        if not all(t.before(source, site) for _, source in (captured, owner)):
            continue
        destinations = {True: set(), False: set()}
        try:
            for expected in (0, 1):
                for actual in (0, 1, 2):
                    known = {captured[0]: expected, owner[0]: actual}
                    def evaluate(value, use=site, trail=()):
                        if value in known:
                            return known[value]
                        if re.fullmatch(r'-?\d+', value):
                            return int(value)
                        require(value in t.defs and value not in trail, 'unbound backend predicate')
                        rhs, definition = t.defs[value]
                        require(t.before(definition, use), 'backend predicate use before definition')
                        return values.evaluate(rhs, lambda item: evaluate(item, definition, (*trail, value)))
                    result = values.integer(evaluate(branch[1]), 1)
                    destinations[actual == expected].add(branch[2] if result else branch[3])
        except ValueError:
            continue  # Other guards may depend on lengths/cancellation/etc.
        if not all(len(group) == 1 for group in destinations.values()):
            continue
        good, bad = next(iter(destinations[True])), next(iter(destinations[False]))
        if good == bad:
            continue
        if good in t.dom.get(t.keyed[0], set()) and not t.can_precede((bad, -1), t.keyed):
            found.append(site)
    require(len(found) == 1, 'backend mismatch/absence can reach keyed selection')
    return found[0]
