"""Complete inspected static ARM startup boundary and public comparison helpers.

No policy learning. Address normalization binds immutable known-answer bytes;
instruction, branch, direction, result-state and comparison operands stay pinned.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('startup_arm_helpers',
        Path(__file__).with_name('aes_accelerated_linked_arm_constructors.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
require, TARGET, arm = c.require, c.TARGET, c.portable
REFERENCE = {k: bytes.fromhex(v) for k,v in json.loads(Path(__file__).with_name('startup-arm-reference.json').read_text()).items()}
POLICY = json.loads(Path(__file__).with_name('startup-arm-review.json').read_text())
NOP = bytes.fromhex('1f2003d5')


def candidates(table):
    selected = {}
    pattern = (r'(?:_ZN30brynja_aes_accelerated_fixture7startup17h[0-9a-f]{16}E|'
               r'_RNvC\w+_30brynja_aes_accelerated_fixture7startup)')
    for line in table.splitlines():
        if 'fixture7startup' not in line and not line.endswith((' bcmp', ' memcmp')):
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized startup symbol row')
        name = match[3]
        role = 'startup' if re.fullmatch(pattern, name) else name
        require(role in ('startup', 'bcmp', 'memcmp') and role not in selected, 'unexpected/duplicate startup symbol')
        selected[role] = name, int(match[1], 16), int(match[2], 16)
    require(set(selected) == {'startup', 'bcmp', 'memcmp'}, 'startup symbol population changed')
    c.cleanup.disjoint(selected.values())
    return selected


def reference_at(image, loads, address, schedule):
    matches = []
    for role, expected in REFERENCE.items():
        if role.startswith('schedule') != schedule:
            continue
        try:
            pos = arm.mapped(loads, address, len(expected), (4, 5))
        except ValueError:
            continue
        if image[pos:pos+len(expected)] == expected:
            matches.append((role, pos, len(expected)))
    require(len(matches) == 1, 'startup reference changed or not uniquely read-only mapped')
    return matches[0]


def observe(lines, raw, row, image, targets):
    require(len(lines)*4 == len(raw) == row[2], 'startup instruction partition changed')
    loads = arm.segments(image)
    pos = arm.mapped(loads, row[1], row[2], 5)
    require(image[pos:pos+len(raw)] == raw, 'startup decoded bytes differ from executable')
    # Only these fully validated address materializations are replaced in the
    # temporary observer input. Their masked encodings AND semantic roles are
    # restored into the final text hash; no original image is modified.
    text, code, replacements, refs = list(lines), bytearray(raw), {}, []
    for i, line in enumerate(lines):
        pc = row[1]+4*i
        word = int.from_bytes(raw[4*i:4*i+4], 'little')
        adr = re.fullmatch(r'adr x(\d+), 0x([0-9a-f]+) <[^>]+>', line)
        page = re.fullmatch(r'adrp x(\d+), 0x([0-9a-f]+) <[^>]+>', line)
        if adr:
            reg, address = int(adr[1]), int(adr[2], 16)
            require(reg < 31 and word & 0x9f00001f == 0x10000000|reg, 'startup ADR encoding mismatch')
            immediate = ((word >> 5) & 0x7ffff) << 2 | (word >> 29) & 3
            require(address == pc + arm.signed(immediate, 21), 'startup ADR destination mismatch')
            ref = reference_at(image, loads, address, True)
            replacements[i] = f'adr x{reg}, @{ref[0]}; encoding={word & 0x9f00001f:08x}'
            refs.append(ref)
        elif page and i+1 < len(lines):
            reg, address = int(page[1]), int(page[2], 16)
            add = re.fullmatch(r'add x'+str(reg)+r', x'+str(reg)+r', #(\d+)', lines[i+1])
            if not add:
                continue  # The common observer binds ADRP + direct vector loads.
            extra = int.from_bytes(raw[4*i+4:4*i+8], 'little'); offset = int(add[1])
            require(reg < 31 and word & 0x9f00001f == 0x90000000|reg, 'startup ADRP encoding mismatch')
            immediate = ((word >> 5) & 0x7ffff) << 2 | (word >> 29) & 3
            require(address == (pc & ~4095) + arm.signed(immediate, 21)*4096, 'startup ADRP destination mismatch')
            require(offset < 4096 and extra == 0x91000000 | (offset<<10) | (reg<<5) | reg,
                    'startup address ADD encoding mismatch')
            ref = reference_at(image, loads, address+offset, False)
            replacements[i] = f'adrp x{reg}, @page; encoding={word & 0x9f00001f:08x}'
            replacements[i+1] = f'add x{reg}, x{reg}, @{ref[0]}; encoding={extra & 0xffc003ff:08x}'
            refs.append(ref)
    for i in replacements:
        text[i] = 'nop'; code[4*i:4*i+4] = NOP
    shadow = image[:pos]+code+image[pos+len(code):]
    actual, constants, normalized = arm.observe(text, bytes(code), row, shadow, targets)
    for i, value in replacements.items(): normalized[i] = value
    require(sorted(role for role, _, _ in refs) == sorted(REFERENCE), 'startup reference population changed')
    actual['text_sha256'] = hashlib.sha256(('\n'.join(normalized)+'\n').encode()).hexdigest()
    actual['address_constants'] = len(refs)
    return actual, [(p,n) for _,p,n in refs]+constants, normalized, refs


def check(lines, raw, row, image, targets, compiler):
    require(compiler in ('1.90.0', '1.99.1'), 'unreviewed startup compiler')
    require(set(targets) == {'bcmp', *(k+str(b) for k in ('expand','round') for b in (128,192,256))},
            'startup call population changed')
    c.cleanup.disjoint([row, *targets.values()])
    actual, _, _, _ = observe(lines, raw, row, image, targets)
    require(actual == POLICY[compiler]['startup'], 'startup stream changed; explicit review required')
    return actual


def compare_check(lines, raw, row, image, targets, compiler, role):
    require(compiler in ('1.90.0','1.99.1') and role in ('bcmp','memcmp'), 'unreviewed startup comparator')
    require(set(targets) == ({'memcmp'} if role == 'bcmp' else set()), 'startup comparator call population changed')
    c.cleanup.disjoint([row, *targets.values()])
    actual, _, _ = arm.observe(lines, raw, row, image, targets, tail_calls=('memcmp',) if role=='bcmp' else ())
    require(actual == POLICY[compiler][role], 'startup comparator stream changed')
    return actual


def mutations(checker, lines, raw, row, image, *args):
    checker(lines, raw, row, image, *args)
    pos = arm.mapped(arm.segments(image), row[1], row[2], 5)
    for i in range(len(lines)+len(raw)):
        text, data, binary = list(lines), raw, image
        if i < len(lines): text[i] = 'unreviewed-instruction'
        else:
            j = i-len(lines); data = raw[:j]+bytes([raw[j]^1])+raw[j+1:]
            binary = image[:pos]+data+image[pos+len(data):]
        try: checker(text, data, row, binary, *args)
        except ValueError as error:
            require(any(s in str(error) for s in ('changed','mismatch','unbound','unconsumed','unreviewed', 'mapped', 'before load',
                                                'control flow crosses pending constant page')),
                    'unrelated startup mutation rejection: '+str(error))
        else: raise ValueError('startup mutation accepted')
    return len(lines)+len(raw)


def inspect(table, assembly, image, compiler, panic):
    require(compiler in ('1.90.0','1.99.1') and panic in ('abort','unwind'), 'unreviewed startup configuration')
    rows = candidates(table)
    dependencies = {'rounds': c.kernels.inspect(table, assembly, image, TARGET),
                    'expansion': c.expansion.inspect(table, assembly, image, TARGET)}
    targets = {'bcmp': rows['bcmp']}
    for kind, reviewer in (('round', c.kernels), ('expand', c.expansion)):
        select = reviewer.select(table, TARGET)
        for row in select:
            bits = reviewer.check(*c.kernels.decode(assembly,row,TARGET),row,image,TARGET)['bits']
            role = kind+str(bits)
            require(role not in targets, 'duplicate startup kernel width')
            targets[role] = row
    c.cleanup.disjoint([*rows.values(), *(row for k,row in targets.items() if k != 'bcmp')])
    rejected, reports = 0, {}
    for role in ('bcmp','memcmp'):
        args = (*c.decode(assembly,rows[role]),rows[role],image,
                {'memcmp':rows['memcmp']} if role=='bcmp' else {},compiler,role)
        reports[role] = compare_check(*args)
        rejected += mutations(compare_check,*args)
    args = (*c.decode(assembly,rows['startup']),rows['startup'],image,targets,compiler)
    reports['startup'] = check(*args)
    rejected += mutations(check,*args)
    _, constants, _, refs = observe(*args[:-1])
    offsets = sorted({p+i for p,n in constants for i in range(n)})
    for pos in offsets:
        binary = image[:pos]+bytes([image[pos]^1])+image[pos+1:]
        try: check(*args[:3],binary,*args[4:])
        except ValueError as error:
            require('reference changed' in str(error) or 'stream changed' in str(error), 'unrelated startup constant rejection')
        else: raise ValueError('startup constant mutation accepted')
    return dict(bodies=reports, rejected_code_mutations=rejected, rejected_constant_mutations=len(offsets),
                references=[dict(role=r, offset=p, size=n) for r,p,n in refs], dependencies=dependencies,
                scope='static ARM startup: wrong backend, complete schedules, six independent answers and terminal health; '
                      'not hosted admission, arbitrary callers, native or physical qualification')


def corruption_cases(image, references):
    require(len(references) == len(REFERENCE) and {r['role'] for r in references} == set(REFERENCE),
            'startup corruption population changed')
    for ref in references:
        role, pos, size = ref['role'], ref['offset'], ref['size']
        expected = REFERENCE[role]
        require(type(pos) is int and pos >= 0 and size == len(expected)
                and image[pos:pos+size] == expected, 'startup corruption reference changed')
        for i in range(size if role.startswith('schedule') else 1):
            yield f'{role}:{i}', image[:pos+i]+bytes([image[pos+i]^1])+image[pos+i+1:]
