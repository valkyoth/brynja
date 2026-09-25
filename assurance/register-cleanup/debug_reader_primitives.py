"""Retained slice/copy/mask bodies; raw-pointer preconditions and assembly stay explicit."""
import re

import check_debug_composed_read as composed

model, require, comparison = composed.model, composed.require, composed.comparison
BASE_CLOSURE = composed.closure


def closure(case, consuming):
    root, producer, names, merged = BASE_CLOSURE(case, consuming)
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('sha3', 'core')}
    boundaries, selected, pending = {}, {}, [(names['split'], 'sha3'), (names['lane_copy'], 'core'), (names['mask'], 'core')]
    while pending:
        name, source = pending.pop()
        if name.startswith('llvm.'):
            require(name == 'llvm.memcpy.p0.p0.i64', 'known descriptor-copy intrinsic')
            continue
        if 'panicking' in name:
            continue  # Invalid-range/pointer panic paths are not qualification inputs.
        if name not in artifacts[source]:
            matches = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(matches) == 1, 'same-row primitive definition: ' + name)
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed primitive/helper ABI')
        roles = {'raw_parts': '18from_raw_parts_mut18precondition_check',
                 'raw_copy': 'secret_memory_transfer10copy_bytes', 'raw_mask': 'secret_memory_mask9mask_byte'}
        role = next((key for key, token in roles.items() if token in name), None)
        if role:
            require(role not in boundaries or boundaries[role] == name, 'one original primitive boundary')
            header = body.splitlines()[0]
            args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
            expected = {'raw_parts': ('ptr', 'i64', 'i64', 'i64', 'ptr'),
                        'raw_copy': ('ptr', 'ptr', 'i64'), 'raw_mask': ('ptr', 'i8', 'i8')}[role]
            require(header.startswith('define internal void @') and len(args) == len(expected)
                    and all(arg.startswith(kind + ' ') for arg, kind in zip(args, expected)), 'exact primitive boundary ABI: ' + role)
            boundaries[role] = name
            continue
        if name in selected:
            require(model.parameters(body) == model.parameters(selected[name]) and model.blocks(body) == model.blocks(selected[name]),
                    'identical cross-crate primitive helper')
            continue
        selected[name] = body
        pending.extend((callee, source) for callee in composed.bridges.bulk.calls(body))
    require(set(boundaries) == {'raw_parts', 'raw_copy', 'raw_mask'} and boundaries['raw_copy'] == names['copy'],
            'original raw primitives, not lookalikes')
    names.update(boundaries)
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical primitive/reader shared helper')
        merged[name] = body
    return root, producer, names, merged


class PrimitiveBodies:
    primitive = None

    def primitive_body(self, role, args, depth):
        require(self.primitive is None, 'no recursive/reentrant primitive wrapper')
        if role == 'split':
            require(len(args) == 5, 'complete split arguments')
            result, source, length, mid, _ = args
            require(type(length) is int and type(mid) is int and 0 <= mid <= length <= model.MASK >> 1,
                    'valid Rust byte-slice split range')
            self.address(source, length, access=False)
            self.address(result, 32)
        elif role == 'lane_copy':
            require(len(args) == 4, 'complete borrowed copy slices')
            destination, length, source, source_length = args
            require(type(length) is int and type(source_length) is int and 0 <= length <= model.MASK >> 1
                    and 0 <= source_length <= model.MASK >> 1, 'valid copy slice widths')
            self.address(destination, length, access=False)
            self.address(source, source_length, access=False)
            require(destination.region != source.region or destination.offset + length <= source.offset
                    or source.offset + source_length <= destination.offset, 'live disjoint borrowed copy regions')
        else:
            require(role == 'mask' and len(args) == 3 and all(type(n) is int and 0 <= n < 256 for n in args[1:]),
                    'one borrowed byte and public byte masks')
            self.address(args[0], 1, access=False)
        self.primitive, self.primitive_args, self.raw_calls = role, args, []
        try:
            value = model.Model.run(self, self.names[role], args, depth)
            if role == 'split':
                fields = [self.load(model.Pointer(result.region, result.offset + offset), 8) for offset in (0, 8, 16, 24)]
                require(value is None and fields == [source, mid, model.Pointer(source.region, source.offset + mid), length - mid],
                        'actual split returns exact disjoint exhaustive original descriptors')
            elif role == 'lane_copy':
                expected = [('copy', destination, source, length)] if length == source_length else []
                require(self.raw_calls == expected and value == (self.names['copy_success'] if length == source_length else 2),
                        'actual equal-length check and exactly one original raw copy, including empty slices')
            else:
                require(value is None and self.raw_calls == [('mask', *args)], 'actual exact single borrowed mask handoff')
            return value
        finally:
            self.primitive = None

    def run(self, name, args, depth=0):
        if self.primitive and name == self.names['raw_parts']:
            result, source, length, mid, _ = self.primitive_args
            require(self.primitive == 'split' and len(args) == 5 and args[1:3] == [1, 1]
                    and (args[0], args[3]) in ((source, mid), (model.Pointer(source.region, source.offset + mid), length - mid)),
                    'original aligned/live byte slices at raw-pointer precondition boundary')
            self.address(args[0], args[3], access=False)
            return None  # Valid borrowed byte pointers; not a proof of this panic/check body.
        if self.primitive and name in (self.names['raw_copy'], self.names['raw_mask']):
            role = 'copy' if name == self.names['raw_copy'] else 'mask'
            expected = ([self.primitive_args[0], self.primitive_args[2], self.primitive_args[1]]
                        if role == 'copy' else self.primitive_args)
            require(self.primitive == ('lane_copy' if role == 'copy' else 'mask') and args == expected,
                    'exact original pointers, widths and public masks at raw assembly boundary')
            self.raw_calls.append((role, *args))
            return None  # Assembly inspected separately; no payload loads in this model.
        if self.primitive and name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[2:] == [32, 0], 'complete nonvolatile split descriptor move')
            destination, source = args[:2]
            self.address(destination, 32)
            self.address(source, 32)
            require(destination.region != source.region, 'nonoverlapping local descriptor move')
            values = [self.load(model.Pointer(source.region, source.offset + offset), 8) for offset in (0, 8, 16, 24)]
            for offset, value in zip((0, 8, 16, 24), values):
                self.store(model.Pointer(destination.region, destination.offset + offset), 8, value)
            return None
        return super().run(name, args, depth)


class PrimitiveModel(PrimitiveBodies, model.Model):
    def __init__(self, functions, constants, names):
        super().__init__(functions, constants, '')
        self.names = names
        self.step_limit = 10000


class ReaderPrimitives(PrimitiveBodies, composed.ComposedRead):
    def run(self, name, args, depth=0):
        if self.primitive is None and self.in_read and name == self.names['split']:
            require(len(args) == 5 and args[1] == model.Pointer('storage', 864 + self.copied)
                    and args[2] == self.length - self.copied and type(args[3]) is int and 0 < args[3] <= args[2],
                    'actual engine splitting original remaining staging')
            return self.primitive_body('split', args, depth)
        if self.primitive is None and name == self.names['lane_copy']:
            # Reuse the established caller checks and fault-injection boundary.
            # The following real wrapper must additionally reach its raw leaf;
            # no expected result descriptor is prefilled for its implementation.
            result = super().run(name, args, depth)
            if result != self.names['copy_success']:
                return result  # Explicit synthetic caller-error probe, not a raw-copy error claim.
            require(self.primitive_body('lane_copy', args, depth) == result, 'actual copy wrapper agrees with caller result')
            return result
        if self.primitive is None and name == self.names['mask']:
            super().run(name, args, depth)  # Original final-chunk check and synthetic unwind probe.
            return self.primitive_body('mask', args, depth)
        return super().run(name, args, depth)
