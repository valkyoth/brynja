"""Exclude inner readiness/digest errors and unwind from MD5 outer dispatch.

Independent compiled Result ABI probes supply discriminants. Unknown payloads
and unmodeled predicates are explored conservatively. This does not establish
the returned error identity, complete owner/report provenance or quarantine.
"""
import re

import legacy_hmac_md5_error_flow as errors

phases = errors.phases
flow, syntax, require, VALUE = errors.flow, errors.syntax, errors.require, errors.VALUE
fence = phases.handoff.fence


def rejection(fixture):
    definitions, aliases = flow.definitions_and_aliases(fixture)
    body = fence.admission.probe(definitions, aliases, "digest_rejection")
    graph = flow.blocks(body)
    require(len(graph) == 1, "MD5 digest rejection probe gained control flow")
    lines = next(iter(graph.values()))
    pointers = syntax.pointers(body, ("%_0",))
    stores = {}
    for line in lines:
        gep = re.fullmatch(rf"({VALUE}) = getelementptr inbounds(?: nuw)? i8, ptr %_0, i64 (1|48)", line)
        store = re.fullmatch(rf"store i8 ({VALUE}|-?\d+), ptr ({VALUE}), align (1|8)", line)
        if gep:
            continue
        if store:
            root, offset = pointers.get(store[2], (None, None))
            require(root == "%_0" and offset not in stores, "unbound/duplicate MD5 error probe store")
            stores[offset] = store[1]
        else:
            require(line == "ret void" and line == lines[-1], "unparsed MD5 rejection probe")
    require(set(stores) == {0, 1, 48} and stores[0] == "%error.0" and stores[1] == "%error.1"
            and stores[48] in ("3", "-1"), "MD5 digest Result layout changed")
    tag = int(stores[48]) & 255
    return tag


def continuation(graph, site):
    label, index = site[:2]
    if "invoke " not in graph[label][index]:
        return (label, index + 1), None
    edge = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL
                        + r"(?:, ![-\w.]+ !\d+)*", graph[label][index + 1])
    require(edge and index + 2 == len(graph[label]), "MD5 result call edges changed")
    return (edge[1], 0), (edge[2], 0)


def sites(body):
    graph = flow.blocks(body)
    inner = phases.one(body, lambda name, args: phases.identity(name, "digest"), "inner result")
    outer = phases.one(body, lambda name, args: phases.identity(name, "outer") and len(args) == 3, "outer result")
    pads = phases.one(body, lambda name, args: phases.identity(name, "pads"), "normalization")
    after_pads = phases.handoff.reachable(graph, pads[0])
    ready = [site for site in phases.calls(body, lambda name, args: fence.identity(name, "ready"))
             if site[0] in after_pads and inner[0] in phases.handoff.reachable(graph, site[0])]
    require(len(ready) == 1, "missing/ambiguous inner readiness")
    return ready[0], inner, outer


def check(signature, body, ok, error_tag, panic):
    graph = flow.blocks(body)
    ready, inner, outer = sites(body)
    phases.dominates(graph, ready, inner)
    phases.dominates(graph, ready, outer)
    require(len(ready[3]) == 1, "MD5 inner readiness arity changed")
    workspace = syntax.operand(inner[3][1])
    authority = syntax.operand(ready[3][0])
    pointers = syntax.pointers(body, (workspace,))
    load = re.search(re.escape(authority) + rf" = load ptr, ptr ({VALUE}),", body)
    require(load and pointers.get(load[1]) == (workspace, 0), "MD5 inner readiness authority changed")
    line = graph[ready[0]][ready[1]]
    returned = re.match(rf"({VALUE}) = (?:tail )?(?:call|invoke) \{{ i8, i8 \}} ", line)
    require(returned, "MD5 inner readiness result discarded")
    start, unwind = continuation(graph, ready)
    stops = {inner[:2], outer[:2]}
    for discriminator in range(4):
        require(not errors.reaches(body, start, ready[0], {returned[1]: (discriminator, None)}, None, None, stops),
                "MD5 inner readiness error reaches hashing")
    require(errors.reaches(body, start, ready[0], {returned[1]: (ok & 255, None)}, None, None, {inner[:2]}),
            "MD5 readiness success has no inner dispatch witness")
    require(not errors.reaches(body, start, ready[0], {returned[1]: (ok & 255, None)}, None, None,
                               {outer[:2]}, barriers={inner[:2]}),
            "MD5 readiness success bypasses inner dispatch")
    require(bool(unwind) == (panic == "unwind"), "MD5 readiness unwind profile changed")
    if unwind:
        require(not errors.reaches(body, unwind, ready[0], {}, None, None, stops),
                "MD5 inner readiness unwind reaches hashing")
    start, unwind = continuation(graph, inner)
    result = syntax.operand(inner[3][0])
    require(not errors.reaches(body, start, inner[0], {}, result, error_tag, {outer[:2]}),
            "MD5 inner digest error reaches outer dispatch")
    # Both real SIMD backend niches must retain a possible successful path;
    # other report fields remain unknown, never assumed valid here.
    for backend in (0, 1):
        require(errors.reaches(body, start, inner[0], {}, result, backend, {outer[:2]}),
                "MD5 successful inner result has no outer dispatch witness")
    require(bool(unwind) == (panic == "unwind"), "MD5 digest unwind profile changed")
    if unwind:
        require(not errors.reaches(body, unwind, inner[0], {}, None, None, {outer[:2]}),
                "MD5 inner digest unwind reaches outer dispatch")


def validate(fixture, llvm, panic):
    ok, error_tag = fence.success(fixture), rejection(fixture)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    for operation in ("authenticate", "authenticate_secret", "verify"):
        check(*phases.rows.method(definitions, aliases, operation)[1], ok, error_tag, panic)
