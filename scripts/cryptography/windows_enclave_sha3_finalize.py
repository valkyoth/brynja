"""Saved scalar finalization/squeezing review, not whole-image qualification."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha3_finalize_shapes as s

u = s.u
t,state,ops,life,shared = u.t,u.state,u.ops,u.life,u.shared
require,digest = u.require,u.digest
SPEC = shared.CATALOG.with_name('sha3-finalize-20261005.json')
SPEC_HASH = '511ba247851b176ff6749cd0273cf882ad67756f6327703ab42469ab62774134'
ROLES = tuple(k+str(rate) for k in ('enter','finalize','squeeze') for rate in (136,168))


def specification(raw):
    require(digest(raw)==SPEC_HASH,'saved finalization specification identity')
    value = json.loads(raw);pins = value['functions']
    require(value['schema']==1 and set(pins)==set(ROLES),'six transition/finalize/squeeze bodies')
    for k,pin in pins.items():
        require(pin['stack_bytes']==(72 if k.startswith('enter') else 168) and not pin['saved_registers'],
                'exact fixed frame')
    return value


def preconditions(raw,pins):
    require(digest(raw)==ops.s.IR_HASH,'same saved private compiler IR');lines = raw.decode().splitlines()
    for role,pin in pins.items():
        matches = [line for line in lines if line.startswith('define internal fastcc ') and '@'+pin['name']+'(' in line]
        require(len(matches)==1,'unique private function ABI');line = matches[0]
        require('dereferenceable(1041)' in line if role.startswith('enter') else 'dereferenceable(1040)' in line,
                'complete owner extent')
        if role.startswith('finalize'):
            require('dereferenceable_or_null(1)' in line and 'range(i8 4, 32)' in line and 'range(i8 3, 6)' in line,
                    'private partial pointer and suffix domains')
        else: require('dereferenceable(32)' in line if role.startswith('enter') else 'dereferenceable(24)' in line,
                      'typed input/output metadata extent')
    return dict(valid_owner_and_borrows_required=True,canonical_partial_bits_required=True,
                finalize_suffix_half_open_range=[4,32],finalize_suffix_width_half_open_range=[3,6],
                arbitrary_private_abi_calls_qualified=False)


def padding(rate,whole,partial,valid,suffix,width):
    """Model inspected block placement; oracle comparison is separate from hashing."""
    require(rate in (136,168) and len(whole)<rate and 0<=partial<=255 and 0<=valid<=7,'canonical tail domain')
    require((suffix,width) in ((4,3),(6,3),(31,5)),'reviewed caller suffixes')
    block = bytearray(rate);block[:len(whole)] = whole;position = len(whole)*8;out = []
    if valid: block[len(whole)] = partial & ((1<<valid)-1);position += valid
    for bit in range(width):
        if position==rate*8: out.append(bytes(block));block = bytearray(rate);position = 0
        if suffix & (1<<bit): block[position//8] |= 1<<(position%8)
        position += 1
    if position==rate*8: out.append(bytes(block));block = bytearray(rate)
    block[-1] |= 128;out.append(bytes(block));return out


def squeeze_plan(rate,position,length,total,capacity,initialized,has_region=True):
    """Metadata-only branch model; no guarantee of rollback for earlier chunks."""
    require(rate in (136,168) and type(position) is int and 0<=position<=255,'rate/cursor domain')
    require(all(type(n) is int and 0<=n<1<<64 for n in (length,capacity,initialized)),'u64 metadata')
    require(length<=2048,'bounded test-model workload, not an API limit')
    next_total = u.counter_admit(total,length);ranges = [];writes = [];clears = 0;permutations = 0
    def result(error): return dict(error=error,position=position,total=next_total if error is None else total,
        initialized=initialized,ranges=ranges,writes=writes,staging_clears=clears,permutations=permutations)
    if next_total is None: return result('OutputTooLong')
    remaining = length
    while remaining:
        count = min(rate,remaining);filled = 0
        while filled<count:
            if position>rate: return result('StateConsumed')
            if position==rate: permutations += 1;position = 0
            take = min(rate-position,count-filled);ranges.append((position,take));position += take;filled += take
        if not has_region or initialized+count>=1<<64 or initialized+count>capacity:
            clears += 1;return result('SecretMemory')
        writes.append(count);initialized += count;clears += 1;remaining -= count
    return result(None)


def connections(records,anchors,external,pins):
    require(set(records)==set(ROLES),'complete six-body population')
    targets = {pin['name']:records[k]['rva'] for k,pin in pins.items()}
    targets.update({r['entry']:r['rva'] for r in external.values()})
    for role,r in records.items():
        kind,rate = role[:-3],int(role[-3:])
        if kind=='enter': expected = {s.ZERO,pins['finalize'+str(rate)]['name'],external['update'+str(rate)]['entry']}
        else:
            keys = ('copy','mask','xor','zero','permutation') if kind=='finalize' else ('copy','copy_bytes','zero','permutation')
            expected = {external[k]['entry'] for k in keys}
        require(set(r['reference_targets'])==expected,'exact operation-specific callee population')
    image_hash = records['enter136']['image_sha256'];reached = set()
    for r in (*records.values(),*anchors,*external.values()):
        require(r['image_sha256']==image_hash,'same image for all connections')
        for name,address in r['reference_targets'].items():
            if name in targets: require(address==targets[name],'actual finalize/squeeze destination');reached.add(name)
    require({pin['name'] for pin in pins.values()}<=reached,'all six helpers reached from reviewed callers')


def geometry(window,parent,owners):
    paths = {}
    for name,start,fixed in (
        ('rehash -> finish_fixed -> finalize136',parent['geometry']['paths']['rehash -> finish_fixed']['rsp_from_high'],168),
        ('squeeze -> squeeze_secret',owners['geometry']['paths']['squeeze']['rsp_from_high'],168),
        ('rehash -> finish_xof -> enter',parent['geometry']['paths']['rehash -> finish_xof']['rsp_from_high'],72)):
        f = life.bounded.Frame.enter(window,window.high+start,fixed)
        paths[name] = dict(rsp_from_high=f.current-window.high,callee=f.unknown_callee('deeper callee entry/home'))
    return dict(paths=paths,outer_window_clearing_required=True,maximum_whole_image_depth_qualified=False)


def inspect(base,mutate=False):
    parent = state.inspect(base);owners = ops.inspect(base);transfer = t.inspect(base);updates = u.inspect(base);lifecycle = life.inspect(base)
    pins = specification(SPEC.read_bytes())['functions'];hp = t.specification(t.SPEC.read_bytes())['functions']
    row = shared.catalog(shared.CATALOG.read_bytes())[3];profile = life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][2]
    directory = (base/row['object']).parent;data = life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image = (base/row['image']).read_bytes();raw = (directory/'normal_rust.s').read_bytes()
    require(digest(raw)==life.ASM_HASH and digest(data)==parent['object_sha256'] and digest(image)==parent['image_sha256'],
            'same saved finalization image/object/assembly')
    pre = preconditions((directory/'normal_rust.ll').read_bytes(),pins)
    text = raw.decode();rows,functions = shared.caller.pe.linked(image)
    anchors = [*parent['records'].values(),*owners['records'].values()];records = {};asm = {};shapes = {};sites = {};mutants = 0
    for role in ROLES:
        pin = pins[role];kind,rate = role[:-3],int(role[-3:]);code,refs = shared.caller.function(data,pin['name']);t.instructions(code,refs,pin)
        label = '\n'+pin['name']+':\n';require(text.count(label)==1,'unique assembly label')
        start = text.index(label);body = text[start:text.index('.seh_endproc',start)]
        s.landmarks(kind,rate,body,hp,pins);sites[role] = s.cleanup(kind,body)
        shapes[role] = s.common_shape(kind,rate,body,pin['name'],pins);asm[role] = digest(body.encode())
        r = ops.memory.handlers.bind(data,image,pin['name'],anchors)
        r['unwind'] = shared.caller.unwind.extent(rows,functions,r['rva'],len(code));records[role] = r;anchors.append(r)
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: t.instructions(bad,refs,pin)
                except ValueError: mutants += 1
                else: raise AssertionError('accepted finalizer/squeezer mutation')
    for kind in ('enter','finalize','squeeze'):
        require(shapes[kind+'136']==shapes[kind+'168'],'only reviewed differences between rate pair')
    ops.frames(records,pins)
    external = {k:transfer['records'][k] for k in ('copy','copy_bytes','mask','xor')}
    external.update(zero=lifecycle['records'][s.ZERO],permutation=updates['permutation_identity_only'])
    external.update({'update'+str(rate):updates['records'][str(rate)] for rate in (136,168)})
    connections(records,anchors,external,pins)
    result = dict(schema=1,status='SAVED_SCALAR_SHA3_FINALIZATION_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
        records=records,assembly_body_sha256=asm,permutation_sites=sites,compiler_preconditions=pre,
        geometry=geometry(life.bounded.Window(0,65536),parent,owners),actual_body_byte_mutations_rejected=mutants,
        whole_image_qualified=False,permutation_internals_qualified=False,terminal_output_adapters_qualified=False,
        arbitrary_exception_cleanup_qualified=False,native_run_added=False,release_gate_changed=False,independently_verified=False)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-finalize.py')))
    result['source_sha256'] = {f.name:digest(f.read_bytes()) for f in sorted(paths)}
    result['spec_sha256'] = digest(SPEC.read_bytes());return result


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--mutate',action='store_true');parser.add_argument('--output',type=Path);a = parser.parse_args()
    text = json.dumps(inspect(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
