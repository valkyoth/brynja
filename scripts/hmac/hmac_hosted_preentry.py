"""Pre-entry error paths, using source-bound pthread/resource return contracts.

Not a new platform guarantee: Attributes::new returns ThreadAttributes only,
and unsuccessful pthread_create starts no worker. The resource source hashes
are checked by hmac_hosted_contracts. Joined errors are tested separately.
"""
import re

import hmac_engine_final as syntax
import hmac_hosted_transaction_values as values

require, V, L = values.require, values.V, values.L


def check(model):
    r = model.r
    attributes = [(p, args) for p, (name, args) in model.calls.items()
                  if '::thread::Attributes' in name and name.endswith('::new')]
    require(len(attributes) == 1, 'pre-entry attribute population')
    point, args = attributes[0]
    result = r.destination(syntax.operand(args[0]))
    # Resource enum ordering differs: Linux includes DumpExclusion, Darwin
    # deliberately does not. These exact source definitions are hash-bound.
    attribute_error = 8 if r.target == 'aarch64-apple-darwin' else 9
    memory = {(result[0], result[1]): 1, (result[0], result[1] + 1): attribute_error}
    scenarios = [{'start': point, 'memory': memory, 'error': attribute_error}]
    create = r.create[0]
    line = r.graph[create[0]][create[1]]
    status = re.match('(' + V + ') = ', line)
    require(status, 'pre-entry create status missing')
    scenarios.append({'start': create, 'env': {status[1]: 1}, 'error': attribute_error + 1})

    # Also exercise the resource admission/foreign/size rejections before the
    # Attributes call. Discover edges which cannot reach either native entry;
    # never model an arbitrary user callback or unknown operation as passing.
    edges = {label: set(re.findall('label %' + L, ' '.join(lines)))
             for label, lines in r.graph.items()}

    def reaches(start, end):
        todo, seen = [start], set()
        while todo:
            node = todo.pop()
            if node == end:
                return True
            if node not in seen:
                seen.add(node)
                todo.extend(edges[node])
        return False

    armed = next(p for p, source in model.quarantine if source == '1')
    for label, lines in r.graph.items():
        for index, line in enumerate(lines):
            branch = re.fullmatch('br i1 (' + V + '), label %' + L + ', label %' + L + r'(?:,.*)?', line)
            if not branch or not index or not r.before(armed, (label, index)):
                continue
            if label == point[0] or not reaches(label, point[0]):
                continue
            for condition, target in ((1, branch[2]), (0, branch[3])):
                if not reaches(target, point[0]) and not reaches(target, create[0]):
                    scenarios.append({'start': (label, index - 1),
                                      'env': {branch[1]: condition}, 'error': attribute_error})
    require(len(scenarios) >= 3, 'missing pre-entry mapping rejection')
    for scenario in scenarios:
        for verifying in (False, True):
            model.run(verifying, False, False, (values.Unknown(), values.Unknown()), False, scenario)
    return len(scenarios) * 2
