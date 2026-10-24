"""Enumerate every emitted write through the returned-object pointer."""
import re

import legacy_hmac_md5_report_return as returned

n, phases, flow, syntax, require, VALUE = returned.n, returned.phases, returned.flow, returned.syntax, returned.require, returned.VALUE


def writes(body):
    pointers = {name: address for name, address in syntax.pointers(body, ('%_0',)).items()
                if address[0] == '%_0'}
    found = []
    for label, lines in flow.blocks(body).items():
        for index, line in enumerate(lines):
            if not set(re.findall(VALUE, line)) & pointers.keys():
                continue
            gep = re.fullmatch(n.pads.descriptors.GEP, line)
            store = re.fullmatch(rf'store (i8|i56|i64|ptr|<2 x i64>) ({VALUE}|\d+|zeroinitializer), ptr ({VALUE}), align \d+(?:, !.*)?', line)
            call = syntax.call(line)
            if gep:
                require(gep[1] in pointers, 'return object address escaped')
            elif store:
                require(store[3] in pointers and store[2] not in pointers, 'return object pointer escaped through store')
                size = 7 if store[1] == 'i56' else n.bits.width(store[1]) // 8
                found.append(((label, index), pointers[store[3]][1], size, store[1], store[2]))
            elif call:
                symbol, args = call
                require(symbol == 'llvm.memcpy.p0.p0.i64' and len(args) == 4 and args[3] == 'i1 false'
                        and re.fullmatch(r'i64 \d+', args[2]) and syntax.operand(args[0]) in pointers
                        and syntax.operand(args[1]) not in pointers, 'return object has unknown effect')
                found.append(((label, index), pointers[syntax.operand(args[0])][1], int(args[2].split()[-1]),
                              'copy', syntax.operand(args[1])))
            else:
                require(False, 'unparsed return object use: ' + line)
    return found


def overlap(offset, size, start, count):
    return set(range(offset, offset + size)) & set(range(start, start + count))
