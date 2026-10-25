"""Ordinary scalar setup failures after admission, before any worker starts.

Uses the same reviewed pthread/resource contracts as the compiled-owner model.
This does not infer a runtime failure from an arbitrary callback or a fatal
path: only modeled attribute/mapping admission and unsuccessful create return.
"""
import re

import legacy_hmac_hosted_transaction as transaction

require, syntax, V, L = transaction.require, transaction.syntax, transaction.V, transaction.L
values = transaction.values


def scenarios(model, boundary):
    r = model.r
    require(not model.compiled and r.before(boundary, r.create[0]), 'ordinary pre-entry boundary changed')
    attributes = [(point, args) for point, (name, args) in model.calls.items()
                  if '::thread::Attributes' in name and name.endswith('::new')]
    require(len(attributes) == 1, 'ordinary pre-entry attribute population')
    point, args = attributes[0]
    require(r.before(boundary, point), 'ordinary attributes precede admission')
    result = r.destination(syntax.operand(args[0]))
    error = 8 if r.target == 'aarch64-apple-darwin' else 9
    memory = {result: 1, (result[0], result[1] + 1): error}
    rows = [{'start': point, 'memory': memory, 'error': error}]
    create = r.create[0]
    status = re.match('(' + V + ') = ', r.graph[create[0]][create[1]])
    require(status, 'ordinary pre-entry create status missing')
    rows.append({'start': create, 'env': {status[1]: 1}, 'error': error + 1})
    edges = {label: set(re.findall('label %' + L, ' '.join(lines))) for label, lines in r.graph.items()}

    def reaches(start, end):
        todo, seen = [start], set()
        while todo:
            node = todo.pop()
            if node == end:
                return True
            if node not in seen:
                require(node in edges, 'ordinary pre-entry unknown edge')
                seen.add(node)
                todo.extend(edges[node])
        return False

    for label, lines in r.graph.items():
        for index, line in enumerate(lines):
            branch = re.fullmatch('br i1 (' + V + '), label %' + L + ', label %' + L + r'(?:,.*)?', line)
            if not branch or not index or not r.before(boundary, (label, index)):
                continue
            if label == point[0] or not reaches(label, point[0]):
                continue
            for condition, target in ((1, branch[2]), (0, branch[3])):
                if not reaches(target, point[0]) and not reaches(target, create[0]):
                    rows.append({'start': (label, index - 1), 'env': {branch[1]: condition}, 'error': error})
    require(len(rows) >= 3, 'ordinary pre-entry mapping rejection missing')
    return rows


def check(model, boundary):
    rows = scenarios(model, boundary)
    for row in rows:
        for verifying in (False, True):
            model.run(verifying, False, False, (values.Unknown(), values.Unknown()), False, row)
    return len(rows) * 2
