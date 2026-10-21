"""Selected worker factory placement/key provenance; not complete cleanup flow."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_capture as capture

require, VALUE = common.require, syntax.VALUE


def check(arguments, body, names, algorithm, compiled):
    params = syntax.parameters(arguments)
    require(len(params) == 1, 'worker callback parameters changed')
    argument = syntax.operand(params[0])
    graph = common.blocks(body)
    dom = capture.dominates(graph)
    definitions, allocations, calls = {}, {}, []
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            point = label, index
            definition = re.match('(' + VALUE + ') = (.*)', line)
            if definition:
                require(definition[1] not in definitions, 'duplicate worker SSA')
                definitions[definition[1]] = definition[2], point
                alloc = re.fullmatch(r'alloca \[(\d+) x i8\], align \d+', definition[2])
                if alloc:
                    allocations[definition[1]] = int(alloc[1])
            # Panic payload destruction can be indirect; it is not inspected by
            # this selected-factory check and remains pending cleanup work.
            if re.search(r'\b(?:call|invoke)\b.*?@', line):
                symbol, args = syntax.call(line)
                calls.append((names.get(symbol, symbol), args, point))

    def before(first, second):
        return (first[0] == second[0] and first[1] < second[1]
                or first[0] != second[0] and first[0] in dom.get(second[0], set()))

    def origin(value, use, trail=()):
        require(value not in trail and len(trail) < 32, 'recursive worker factory provenance')
        if value == argument:
            return 'job', 0
        require(value in definitions, 'unknown worker factory input')
        rhs, point = definitions[value]
        require(before(point, use), 'worker value does not dominate factory use')
        if value in allocations:
            return value, 0
        gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + VALUE + r'), i64 (\d+)', rhs)
        load = re.match(r'load (ptr|i64|i8), ptr (' + VALUE + '),', rhs)
        if gep:
            root, offset = origin(gep[1], point, (*trail, value))
            return root, offset + int(gep[2])
        require(load, 'unknown worker key/authority factory value: ' + rhs)
        source = origin(load[2], point, (*trail, value))
        key = 24 if compiled else 16
        expected = {('job', key, 'ptr'): ('key', 0),
                    ('job', key + 8, 'i64'): ('key-length', 0),
                    ('job', 8, 'ptr'): ('kernel', 0),
                    ('kernel', 0, 'i8'): ('kernel-value', 0)}
        require((*source, load[1]) in expected, 'worker factory input not from exact launch field')
        return expected[*source, load[1]]

    def local(arg, point):
        root, offset = origin(syntax.operand(arg), point)
        extent = re.search(r'dereferenceable\((\d+)\)', arg)
        require(root in allocations and extent and offset >= 0
                and 0 < int(extent[1]) <= allocations[root] - offset,
                'worker factory destination not in local allocation')

    factory = ('<brynja_mac_hmac::execution::Hmac<' + algorithm + '>>::create' if compiled else
               '<brynja_mac_hmac::engine::Engine<' + algorithm + '>>::new_with::<<' + algorithm
               + ' as brynja_mac_hmac::algorithms::sealed::Hash>::start>')
    factories = [(name, args, point) for name, args, point in calls
                 if 'brynja_mac_hmac::' in name and ('::new_with::<' in name or name.endswith('>::create'))]
    # Abort builds can merge the Full/Bytes constructor sites into one call.
    require(len(factories) in (1, 2),
            'worker key factory population changed: ' + repr((algorithm, compiled, factories)))
    for name, args, point in factories:
        require(name == factory, 'wrong worker key factory identity')
        require(len(args) == (5 if compiled else 4), 'worker key factory signature changed')
        local(args[0], point)
        key_index = 2 if compiled else 1
        require(origin(syntax.operand(args[key_index]), point) == ('key', 0), 'worker key pointer changed')
        length = re.search('(' + VALUE + ')$', args[key_index + 1])
        require(length and args[key_index + 1].startswith('i64 ')
                and origin(length[1], point) == ('key-length', 0), 'worker key length changed')
        if compiled:
            root, offset = origin(syntax.operand(args[1]), point)
            require(root in allocations and offset == 0 and allocations[root] == 16,
                    'borrowed authority is not worker-local: ' + repr((root, offset, allocations.get(root))))
    authorities = [(args, point) for name, args, point in calls
                   if name == '<brynja_crypto_cpu::static_execution::Authority>::new']
    require(len(authorities) == int(compiled), 'worker authority factory population changed')
    for args, point in authorities:
        require(len(args) == 2, 'worker authority factory signature changed')
        local(args[0], point)
        kernel = re.search('(' + VALUE + ')$', args[1])
        require(kernel and args[1].startswith('i8 ') and origin(kernel[1], point) == ('kernel-value', 0),
                'worker authority not from captured kernel')
