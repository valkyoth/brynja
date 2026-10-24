"""Legacy retained/transfer storage bounds and lifetimes, not spill erasure."""
import re

import legacy_hmac_hosted_keyed as keyed

shared = keyed.authority.shared.load('hmac_hosted_storage')
require, syntax, V = keyed.require, keyed.syntax, keyed.V


def check(model):
    roots, copies = set(model.roots), {}
    for mode, site, dest, args in model.writes:
        if mode != 'copy' or not model.before(model.cut, site):
            continue
        source = model.pointer(syntax.operand(args[1]), site)
        if not source or source[0] != model.owner:
            continue
        destination = model.pointer(dest, site)
        allowed = {912, 904} if model.identity == 'sha1_compiled' else set()
        require(source == (model.owner, 0) and args[2] in {'i64 ' + str(n) for n in allowed}
                and args[3] == 'i1 false' and destination and destination[1] == 0
                and destination[0] not in roots and model.allocs[destination[0]] == int(args[2].split()[-1]),
                'legacy retained transfer geometry changed')
        copies[destination[0]] = site
        roots.add(destination[0])
    require(len(copies) >= 2 if model.identity == 'sha1_compiled' else not copies,
            'legacy retained terminal transfer population changed')
    aliases = {name for name in model.defs if (p := model.pointer(name)) and p[0] in roots}
    uses, starts, ends = ({root: set() for root in roots}, {root: [] for root in roots},
                         {root: [] for root in roots})

    def address(value):
        result = model.pointer(value)
        return result if result and result[0] in roots else None

    def use(value, size, site):
        pointer = address(value)
        if pointer:
            root, offset = pointer
            require(0 <= offset <= model.allocs[root] - size, 'legacy retained access outside allocation')
            uses[root].add(site)

    for label, lines in model.graph.items():
        for index, line in enumerate(lines):
            site = label, index
            mentioned = set(re.findall(V, line)) & aliases
            if not mentioned:
                continue
            define = re.match('(' + V + ') = (.*)', line)
            if define and define[1] in model.allocs:
                continue
            if define and define[2].startswith('getelementptr'):
                p = address(define[1])
                require(p and 0 <= p[1] < model.allocs[p[0]], 'unreviewed retained pointer arithmetic')
                continue
            load = re.match('(' + V + r') = load (ptr|i\d+), ptr (' + V + '),', line)
            store = re.match(r'store (ptr|i\d+) (.+), ptr (' + V + '),', line)
            if load:
                use(load[3], 8 if load[2] == 'ptr' else (int(load[2][1:]) + 7) // 8, site)
            elif store:
                require(mentioned == {store[3]}, 'legacy retained pointer stored as value')
                use(store[3], 8 if store[1] == 'ptr' else (int(store[1][1:]) + 7) // 8, site)
            elif site in model.call_map:
                symbol, args = model.call_map[site]
                if symbol.startswith('llvm.lifetime.'):
                    require(symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'), 'unknown retained lifetime')
                    p = address(syntax.operand(args[-1]))
                    require(p and p[1] == 0 and (len(args) == 1 or args[0] == 'i64 ' + str(model.allocs[p[0]])),
                            'partial legacy retained lifetime')
                    (starts if symbol == 'llvm.lifetime.start.p0' else ends)[p[0]].append(site)
                    continue
                for argument in args:
                    if argument.startswith('ptr '):
                        extent = re.search(r'dereferenceable\((\d+)\)', argument)
                        use(syntax.operand(argument), int(extent[1]) if extent else 1, site)
                if symbol == 'llvm.memcpy.p0.p0.i64':
                    size = re.fullmatch(r'i64 (\d+)', args[2])
                    require(size and args[3] == 'i1 false', 'unknown legacy retained memcpy extent')
                    for argument in args[:2]:
                        use(syntax.operand(argument), int(size[1]), site)
            else:
                require(False, 'unreviewed legacy retained alias/escape: ' + line)
    for root in roots:
        require(len(starts[root]) == 1 and uses[root], 'missing/ambiguous legacy retained lifetime start')
        require(all(model.before(starts[root][0], site) for site in uses[root]), 'legacy retained use before lifetime')
        for end in ends[root]:
            require(not shared.after_end(model, end, starts[root][0], uses[root]), 'legacy retained use after lifetime')
        if root in copies:
            require(all(site == copies[root] or model.before(copies[root], site) for site in uses[root]),
                    'legacy retained transfer used before copy')
    return roots, copies, uses, starts, ends
