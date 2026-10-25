"""Compiled legacy constructor Result-to-retained-state provenance.

The shared byte/lifetime interpreter is reused unchanged, with the actual legacy
layouts and calls. This does not qualify key hashing or destruction in callees.
MD5's selector is not itself a key owner; SHA-1's terminal moves are consuming.
"""
import re

import legacy_hmac_hosted_authority as authority

model = authority.shared.load('hmac_hosted_keyed')
flow, syntax, require, V = authority.flow, authority.syntax, authority.require, authority.V
PREFIX = {'sha1_compiled': '<brynja_legacy_hmac::execution::Sha1Hmac>',
          'md5_compiled': '<brynja_legacy_hmac::md5_batch::Md5Batch>'}


class Admission(model.Admission):
    def __init__(self, body, names, compiler, identity):
        authority.model.Transfer.__init__(self, body, names, compiler)
        require(identity in PREFIX, 'unreviewed legacy keyed identity')
        self.identity, self.compiled, self.payload, self.failure = identity, True, 0, 2
        self.size, self.discriminator = (912, 904) if identity == 'sha1_compiled' else (24, 16)
        self.factories = {site: self.pointer(syntax.operand(args[0]), site)
                          for symbol, args, site in self.calls
                          if names.get(symbol) == authority.KEYED[identity]}
        require(len(self.factories) == 1, 'legacy keyed constructor population')
        for pointer in self.factories.values():
            require(pointer and pointer[1] == 0 and self.allocs[pointer[0]] == self.size,
                    'legacy keyed Result geometry changed')
        self.results = {pointer[0] for pointer in self.factories.values()}
        operations = ({'verify_bits': (0, 4), 'finalize_bits_secret': (1, 5)} if identity == 'sha1_compiled'
                      else {'verify_inner': (1, 5), 'authenticate_secret': (1, 5)})
        self.consumers = []
        for operation, (argument, arity) in operations.items():
            selected = [(args, site) for symbol, args, site in self.calls
                        if names.get(symbol) == PREFIX[identity] + '::' + operation]
            require(len(selected) == 1, 'legacy keyed terminal population: ' + operation)
            args, site = selected[0]
            require(len(args) == arity, 'legacy keyed consumer arity changed')
            pointer = self.pointer(syntax.operand(args[argument]), site)
            require(pointer and pointer[1] == 0 and self.allocs[pointer[0]] == self.size,
                    'legacy keyed consumer owner geometry changed')
            self.consumers.append((pointer[0], site, argument))
        self.terminals, owners, move_sites = [], set(), []
        if identity == 'sha1_compiled':
            for root, site, _ in self.consumers:
                moves = [(point, self.pointer(syntax.operand(data[1]), point))
                         for mode, point, dest, data in self.writes if mode == 'copy'
                         and self.pointer(dest, point) == (root, 0) and self.before(point, site)
                         and data[2:] == ['i64 912', 'i1 false']]
                require(len(moves) == 1, 'legacy keyed terminal move absent/ambiguous')
                self.terminals.append((root, site, moves[0][0]))
                owners.add(moves[0][1])
                move_sites.append(moves[0][0])
            require(len({root for root, _, _ in self.terminals}) == 2, 'legacy terminal storage overlaps')
        else:
            owners = {(root, 0) for root, _, _ in self.consumers}
            move_sites = [site for _, site, _ in self.consumers]
        require(len(owners) == 1, 'legacy keyed consumers use different retained state')
        owner = owners.pop()
        require(owner and owner[1] == 0 and owner[0] not in self.results
                and self.allocs[owner[0]] == self.size, 'legacy retained owner geometry changed')
        self.owner = owner[0]
        self.initial = [site for _, site, dest, _ in self.writes
                        if (p := self.pointer(dest, site)) and p[0] == self.owner
                        and all(self.before(site, use) for use in move_sites)]
        require(self.initial, 'legacy keyed initialization missing')
        last = [site for site in self.initial if all(other == site or self.before(other, site)
                                                     for other in self.initial)]
        require(len(last) == 1, 'legacy initialization lacks completion point')
        self.cut = last[0]
        self.roots = {self.owner, *self.results}
        changed = True
        while changed:
            changed = False
            for mode, site, dest, data in self.writes:
                pointer = self.pointer(dest, site)
                if (mode == 'copy' and pointer and pointer[0] in self.roots
                        and (site == self.cut or self.can_precede(site, self.cut))):
                    source = self.pointer(syntax.operand(data[1]), site)
                    require(source, 'unknown legacy keyed copy source')
                    if source[0] not in self.roots:
                        self.roots.add(source[0])
                        changed = True
        self.edges = {label: re.findall(r'label %' + flow.LABEL, '\n'.join(lines))
                      for label, lines in self.graph.items()}
        self.ancestors = {self.cut[0]}
        while True:
            parents = {label for label, edges in self.edges.items() if set(edges) & self.ancestors}
            if parents <= self.ancestors:
                break
            self.ancestors |= parents
        self.call_map = {site: (symbol, args) for symbol, args, site in self.calls}
        self.write_map = {site: (mode, dest, data) for mode, site, dest, data in self.writes}
        self.aliases = {name for name in self.defs if self.address(name)}
        self.initial_uses()

    def terminal_handoffs(self):
        if self.identity == 'sha1_compiled':
            super().terminal_handoffs()
        else:
            # Unlike SHA-1 finalizers these borrow a non-secret selector. Exact
            # storage/lifetime checking after admission is separate below.
            for _, site, _ in self.consumers:
                require(self.before(self.cut, site), 'legacy selector borrowed before complete initialization')
        for root, site, argument in self.consumers:
            _, args = self.call_map[site]
            mentioned = [(i, self.pointer(syntax.operand(arg), site)) for i, arg in enumerate(args)
                         if arg.startswith('ptr ') and self.pointer(syntax.operand(arg))
                         and self.pointer(syntax.operand(arg))[0] in {root, *self.roots}]
            require(mentioned == [(argument, (root, 0))], 'legacy keyed state hidden in another argument')


def check(body, names, compiler, identity):
    return Admission(body, names, compiler, identity).check()
