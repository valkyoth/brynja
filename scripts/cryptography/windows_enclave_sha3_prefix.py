"""Review saved scalar cSHAKE prefix helpers, not transitive sponge semantics."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha3_transfers as t

state,ops,life,shared = t.state,t.ops,t.life,t.shared
require,digest = t.require,t.digest
SPEC = shared.CATALOG.with_name('sha3-prefix-20261005.json')
SPEC_HASH = '9accd9b3b02d2bf673c9684f1d42aa3178aa279d2c7e16be747098c33a91dba7'
ROLES = ('string128','bits128','string256','bits256')
UPDATE = {k:state.s.UPDATE+v+'_E6updateB6_' for k,v in (('128','a8'),('256','88'))}


def specification(raw):
    require(digest(raw)==SPEC_HASH,'reviewed prefix specification identity')
    result = json.loads(raw);pins = result['functions']
    require(result['schema']==1 and set(pins)==set(ROLES),'four prefix helper bodies')
    for role,p in pins.items():
        require(p['stack_bytes']==(360 if role.startswith('string') else 120) and not p['saved_registers'],
                'reviewed prefix frame')
    for kind in ('string','bits'):
        require(pins[kind+'128']['code_hex']==pins[kind+'256']['code_hex'],'identical rate-pair opcode shapes')
    return result


def sequences(role,pins,helpers):
    rate = role[-3:];update = UPDATE[rate]
    if role.startswith('string'):
        bits = pins['bits'+rate]['name']
        return (
            'movq %rdi, %rdx|xorl %r8d, %r8d|callq '+helpers['encode']['name'],
            'movzwl 302(%rsp), %eax|cmpl $257, %eax|movl $1, %r15d|cmovbq %r12, %r15|cmovbl %eax, %r14d',
            'cmpb $0, 24(%rsi)|je .LBBSTR_1',
            'movq 16(%rsi), %r12|addq %r14, %r12|jb .LBBSTR_16',
            'callq '+update+'|testb %al, %al|jne .LBBSTR_16|movq %r12, 16(%rsi)',
            'shrq $3, %rdi|movq 8(%rbx), %r12|movb $1, %al|cmpq %r12, %rdi|ja .LBBSTR_17',
            'movq 16(%rsi), %r15|addq %rdi, %r15|jb .LBBSTR_16',
            'callq '+update+'|testb %al, %al|jne .LBBSTR_16|movq %r15, 16(%rsi)',
            'movzbl 24(%rbx), %r8d|leal -1(%r8), %eax|cmpb $6, %al|ja .LBBSTR_13|cmpq %r12, %rdi|jae .LBBSTR_16',
            'callq '+bits+'|testb %al, %al|je .LBBSTR_13',
            '.LBBSTR_16:|movb $1, %al', '.LBBSTR_13:|xorl %eax, %eax|jmp .LBBSTR_17')
    return (
        'leal -1(%rdi), %eax|cmpb $8, %al|setb %al|movzbl 24(%rcx), %r13d|cmpb $8, %r13b|setb %cl|andb %al, %cl|movb $1, %al|cmpb $1, %cl|jne .LBBITS_14',
        'cmpb $8, %r13b|ja .LBBITS_13',
        'movl %edi, %eax|subb %bpl, %al|movb $8, %cl|subb %r13b, %cl|movzbl %cl, %ecx|movzbl %al, %r12d|cmpb %r12b, %cl|cmovbl %ecx, %r12d',
        'callq '+helpers['xor']['name']+'|testb %al, %al|jne .LBBITS_13|addb %r12b, %bpl|jb .LBBITS_13',
        'addb %r13b, %r12b|movb %r12b, 24(%r14)|cmpb $8, %r12b|jne .LBBITS_2|incq %rsi|je .LBBITS_13',
        'movl $1, %r8d|movq %r15, %rdx|callq '+update+'|testb %al, %al|jne .LBBITS_13|movq %rsi, 16(%r14)',
        'movl $1, %edx|movq %r15, %rcx|callq '+state.s.ZERO+'|movb $0, 24(%r14)|xorl %r12d, %r12d|jmp .LBBITS_2',
        '.LBBITS_13:|movb $1, %al|jmp .LBBITS_14', '.LBBITS_12:|xorl %eax, %eax')


def landmarks(role,body,pins,helpers):
    text = state.s.normalized(body)
    for number,kind in ((29,'STR'),(31,'STR'),(30,'ITS'),(32,'ITS')):
        text = text.replace('.LBB'+str(number)+'_', '.LBB'+kind+'_')
    for sequence in sequences(role,pins,helpers):
        require(sequence.replace('|','\n') in text,'prefix admission/commit/cleanup landmark: '+role)


def assembly(raw,pins,helpers):
    require(digest(raw)==life.ASM_HASH,'saved prefix assembly identity');text = raw.decode();out = {}
    for role,pin in pins.items():
        label = '\n'+pin['name']+':\n';require(text.count(label)==1,'unique prefix assembly label')
        start = text.index(label);body = text[start:text.index('.seh_endproc',start)]
        landmarks(role,body,pins,helpers);out[role] = digest(body.encode())
        if role.startswith('string'):
            require(body.count('callq\t'+pins['bits'+role[-3:]]['name'])==3,'three encoded prefix/input/tail bit paths')
    return out


def connections(records,parent,helpers,updates,pins):
    require(set(records)==set(ROLES) and set(updates)==set(UPDATE),'complete prefix/callee population')
    image_hash = parent['image_sha256']
    targets = {p['name']:records[k]['rva'] for k,p in pins.items()}
    targets.update({r['entry']:r['rva'] for r in helpers.values()})
    targets.update({r['entry']:r['rva'] for r in updates.values()})
    for role,r in records.items():
        rate = role[-3:]
        expected = {UPDATE[rate], helpers['encode']['entry'], pins['bits'+rate]['name']} if role.startswith('string') else {
            UPDATE[rate],helpers['xor']['entry'],state.s.ZERO}
        require(set(r['reference_targets'])==expected,'exact rate-specific helper closure')
    for r in (*records.values(),*helpers.values(),*updates.values(),parent['records']['new']):
        require(r['image_sha256']==image_hash,'same prefix/callee image')
        for name,address in r['reference_targets'].items():
            if name in targets: require(address==targets[name],'actual prefix/callee destination')
    for rate in UPDATE:
        require(parent['records']['new']['reference_targets'].get(pins['string'+rate]['name'])==records['string'+rate]['rva'],
                'constructor reaches both rate-specific prefix chains')


def geometry(window,parent):
    out = {}
    for path in ('begin -> new','rehash -> new'):
        start = window.high+parent['geometry']['paths'][path]['rsp_from_high']
        string = life.bounded.Frame.enter(window,start,360)
        bits = life.bounded.Frame.enter(window,string.current,120)
        encode = life.bounded.Frame.enter(window,string.current,344)
        xor = life.bounded.Frame.enter(window,bits.current,56)
        out[path] = dict(string_rsp=string.current-window.high,bits_rsp=bits.current-window.high,
            encode_rsp=encode.current-window.high,xor_leaf_entry=xor.current-8-window.high,
            spans=[string.slot('public encoded length',46,258),bits.slot('public bit offset',32,1),
                   bits.slot('absorber pointer',48,8)],update_entry=bits.unknown_callee('sponge update entry/home'))
    return dict(paths=out,outer_window_clearing_required=True,maximum_whole_image_depth_qualified=False)


def push_bits(pending,used,emitted,source,valid,fail_update=False):
    """Inspected control-flow model; failed flush deliberately leaves pending data.

    Constructor error cleanup, not this helper, erases that failed partial work.
    """
    require(all(type(n) is int and 0<=n<=255 for n in (pending,used,source,valid)),'byte domains')
    require(type(emitted) is int and 0<=emitted<1<<64,'public u64 count')
    calls = [];clears = 0
    def result(ok): return dict(ok=ok,pending=pending,used=used,emitted=emitted,calls=calls,clears=clears)
    if not 1<=valid<=8 or used>=8: return result(False)
    position = 0
    while position<valid:
        count = min(valid-position,8-used)
        pending ^= t.xor_contract(source,position,count,used)
        position += count;used += count
        if used==8:
            if emitted==(1<<64)-1: return result(False)
            calls.append(pending)
            if fail_update: return result(False)
            emitted += 1;pending = 0;used = 0;clears += 1
    return result(True)


def inspect(base,mutate=False):
    parent = state.inspect(base);transfer = t.inspect(base);lifecycle = life.inspect(base)
    pins = specification(SPEC.read_bytes())['functions'];hp = t.specification(t.SPEC.read_bytes())['functions']
    row = shared.catalog(shared.CATALOG.read_bytes())[3]
    profile = life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][2];directory = (base/row['object']).parent
    data = life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image = (base/row['image']).read_bytes();rows,functions = shared.caller.pe.linked(image)
    require(digest(data)==parent['object_sha256'] and digest(image)==parent['image_sha256'],'same saved prefix object/image')
    asm = assembly((directory/'normal_rust.s').read_bytes(),pins,hp);records = {};mutants = 0
    anchors = list(parent['records'].values())
    for role in ROLES:
        pin = pins[role];code,refs = shared.caller.function(data,pin['name']);t.instructions(code,refs,pin)
        r = ops.memory.handlers.bind(data,image,pin['name'],anchors)
        r['unwind'] = shared.caller.unwind.extent(rows,functions,r['rva'],len(code))
        records[role] = r;anchors.append(r)
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: t.instructions(bad,refs,pin)
                except ValueError: mutants += 1
                else: raise AssertionError('accepted prefix instruction mutation')
    ops.frames(records,pins)
    updates = {k:ops.memory.handlers.bind(data,image,n,anchors) for k,n in UPDATE.items()}
    helpers = {k:transfer['records'][k] for k in ('encode','xor')}
    helpers['zero'] = lifecycle['records'][state.s.ZERO]
    connections(records,parent,helpers,updates,pins)
    result = dict(schema=1,status='SAVED_SCALAR_SHA3_PREFIX_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
        records=records,assembly_body_sha256=asm,update_callees_identity_only=updates,
        geometry=geometry(life.bounded.Window(0,65536),parent),actual_body_byte_mutations_rejected=mutants,
        valid_typed_borrows_required=True,whole_image_qualified=False,sponge_internals_qualified=False,
        arbitrary_exception_cleanup_qualified=False,native_run_added=False,release_gate_changed=False,independently_verified=False)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-prefix.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    result['spec_sha256'] = digest(SPEC.read_bytes());return result


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path);a = p.parse_args()
    text = json.dumps(inspect(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
