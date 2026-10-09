"""Actual scalar empty N/S constructor paths; not general cSHAKE qualification."""
import re
import windows_enclave_sha3_batch_start as start
import windows_enclave_sha3_avx2_chain as object_review

life,s,L=start.life,start.s,start.shapes.L
NAMES={bits:f'_RNvMs{index}_NtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened6cshakeNtB5_17HardenedCshake{bits}8new_bits'
       for bits,index in ((128,4),(256,6))}
DISPATCH=[27,37,35,36,33,40]
SETUP=L('''.B26:|xorps %xmm0, %xmm0|movups %xmm0, 1657(%rsp)
    movq $1, 1648(%rsp)|movb $0, 1656(%rsp)|movzbl %al, %eax
    leaq .LJTI46_1(%rip), %rcx|movslq (%rcx,%rax,4), %rax
    addq %rcx, %rax|jmpq *%rax''')
PREFIX=L('''pushq %r15|pushq %r14|pushq %r12|pushq %rsi|pushq %rdi|pushq %rbx
    subq $1624, %rsp|movq %r8, %rdi|movq %rdx, %rbx|movq %rcx, %rsi
    xorl %r12d, %r12d|leaq 584(%rsp), %r14|movl $1040, %r8d
    movq %r14, %rcx|xorl %edx, %edx|callq memset|movq %r14, 40(%rsp)
    movq 16(%rbx), %r14|movq 16(%rdi), %r15|movq %r14, %rax|orq %r15, %rax
    jne .B1|.B16:|leaq 616(%rsp), %rax|movups 584(%rsp), %xmm0
    movups %xmm0, (%rax)|movb %r12b, 1620(%rsp)|leaq 1(%rsi), %rcx
    leaq 584(%rsp), %rdx|movl $1040, %r8d|callq memcpy|xorl %eax, %eax|jmp .B17''')
RETURN=L('''.B17:|movb %al, (%rsi)|addq $1624, %rsp|popq %rbx|popq %rdi
    popq %rsi|popq %r12|popq %r14|popq %r15|retq''')


def caller_slice(bits):
    return L(f'''.B{33 if bits==128 else 40}:|movq %rbp, %rdi
        leaq 1680(%rsp), %rcx|leaq 1648(%rsp), %rdx|movq %rdx, %r8|callq {NAMES[bits]}''')


def incoming(data,caller):
    """Account for ALL relocations into either helper section, including aliases."""
    rows,syms=object_review.obj.tables(data)
    symbols={}
    for name in [caller,*NAMES.values()]:
        matches=[v for v in syms.values() if v['name']==name]
        s.require(len(matches)==1 and matches[0]['kind']==32 and matches[0]['value']==0,
                  'unique complete constructor/caller symbol')
        symbols[name]=matches[0]
    result=[]
    for bits,name in NAMES.items():
        section=symbols[name]['section'];entries=[]
        # Do not derive this extent from .pdata: that would let a shortened
        # runtime range validate itself. Each helper owns its complete section.
        code=rows[section-1]['code']
        for row_index,row in enumerate(rows,1):
            for offset,ref in object_review.obj.relocations(data,row,syms).items():
                sym=syms[ref['symbol']]
                if sym['section']!=section:continue
                entries.append((row_index,row['name'],offset,ref['kind'],sym['name'],sym['value'],
                    int.from_bytes(row['code'][offset:offset+4],'little')))
        calls=[v for v in entries if v[1]!=b'.pdata']
        s.require(calls==[(symbols[caller]['section'],b'.text',2495 if bits==128 else 5173,4,name,0,0)],
                  'sole direct caller, no helper address exposure or interior-entry alias')
        pdata=[v for v in entries if v[1]==b'.pdata']
        s.require(len(pdata)==2 and pdata[0][0]==pdata[1][0] and
            [v[2:] for v in pdata]==[(0,3,'.text',0,0),(4,3,'.text',0,len(code))],
            'only exact constructor runtime begin/end metadata references')
        result.append(dict(function=name,caller=caller,call_operand_offset=calls[0][2],
            direct_calls=1,runtime_extent_references=2))
    return result


def predecessors(lines):
    """Conservative whole-start CFG; unknown transfers fail rather than disappear."""
    labels={l[:-1]:i for i,l in enumerate(lines) if l.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in lines),'unique CFG labels')
    pred={i:set() for i in range(len(lines))};indirect=[]
    for i,line in enumerate(lines):
        if line=='retq':targets=[]
        elif line.startswith('j'):
            op,target=line.split()
            if target.startswith('*'):
                s.require(line in ('jmpq *%rcx','jmpq *%rax'),'only two enumerated start dispatches')
                indirect.append(line)
                values=start.TABLES['scalar'][1] if target=='*%rcx' else DISPATCH
                s.require(all(f'.B{n}' in labels for n in values),'all dispatch labels present')
                targets=[labels[f'.B{n}'] for n in values]
            else:
                s.require(target in labels,'all direct CFG targets local and present')
                targets=[labels[target]]+([] if op in ('jmp','jmpq') else [i+1])
        else:targets=[i+1]
        for target in targets:
            s.require(target in pred,'no fall-through beyond start function');pred[target].add(i)
    s.require(indirect==['jmpq *%rcx','jmpq *%rax'],'exact dispatch population/order')
    return pred


def check_caller(bodies,assembly):
    names,_,_=start.check_shapes(bodies,assembly,'scalar')
    lines=life.code(bodies[names['start']]);at=lines.index('.B26:')
    s.require(lines[at:at+len(SETUP)]==SETUP,'empty descriptor and secondary dispatch construction')
    table='.LJTI46_1'
    found=re.findall(r'^'+re.escape(table)+r':\n((?:\s*\.long[^\n]+\n)+)',assembly,re.M)
    s.require(len(found)==1 and [re.sub(r'\s+','',l) for l in found[0].splitlines()]==[
        f'.long.LBB46_{n}-{table}' for n in DISPATCH],'all secondary constructor targets')
    pred=predecessors(lines);out={}
    for bits,name in NAMES.items():
        part=caller_slice(bits);begin=lines.index(part[0]);end=begin+len(part)-1
        s.require(lines[begin:end+1]==part,'same empty readonly N/S descriptor and disjoint result')
        seen=set();pending=[end]
        while pending:
            index=pending.pop()
            if index in seen:continue
            seen.add(index)
            if index!=at:pending.extend(pred[index])
        s.require(seen==set(range(at,at+len(SETUP)))|set(range(begin,end+1)),
                  'descriptor construction dominates helper; no intervening writes or bypass entry')
        out[str(bits)]=dict(caller_instruction_positions=sorted(seen),call=name)
    return names['start'],out


def check_helper(bodies,ir,bits):
    name=NAMES[bits];lines=life.code(bodies[name])
    s.require(len(lines)==(199 if bits==128 else 203),'complete scalar helper extent')
    s.require(lines[:len(PREFIX)]==PREFIX and lines[-len(RETURN):]==RETURN,
              'complete reachable empty constructor instructions and return')
    s.require(lines.count('.B17:')==1,'unique successful return target')
    abi=life.reuse.abi(ir,name)
    output='ptr dead_on_unwind noalias nofree noundef nonnull writable writeonly align 1 captures(none) dereferenceable(1041) initializes((0, 2)) %0'
    source='ptr dead_on_return noalias nofree noundef nonnull readonly align 8 captures(none) dereferenceable(32)'
    s.require(abi.startswith('define internal fastcc void @'+name+'(') and
        '('+output+', '+source+' %1, '+source+' %2)' in abi and ' nounwind ' in abi,
        'private nounwind constructor: exclusive full result and readonly full descriptors')
    return dict(function=name,reachable_instruction_positions=len(PREFIX)+len(RETURN),
        zeroed_local_owner=[584,1624],owner_bytes=1040,result_bytes=1041,
        mode_byte_offset=1036,result_success_tag=0,input_payload_read=False,
        nonempty_constructor_path_qualified=False,local_copy_erased_before_return=False)


def geometry():
    # Caller writes only meaningful descriptor bytes; padding need not be initialized.
    defined=set(range(1648,1656))|{1656}|set(range(1657,1673))
    s.require(set(range(1664,1672))<=defined,'both descriptor bit lengths initialized to zero')
    s.require(1648%8==0 and 1648+32==1680 and 1680+1041<=7168,
              'aligned 32-byte descriptor disjoint from full result and saved XMM6')
    # Six pushed registers and the local frame preserve Win64 16-byte call alignment.
    s.require((8-48-1624)%16==0 and 584+1040==1624,'helper frame and zero-owner extent')
    s.require(584<=616<616+16<=1624 and 1620==584+1036,'counter copy and mode within zero owner')
    return dict(descriptor_span=[1648,1680],result_span=[1680,2721],
        descriptor_bit_length_span=[1664,1672],helper_frame_bytes=1624,saved_gpr_bytes=48,
        result_entirely_initialized=True,descriptor_padding_read=False,
        runtime_memcpy_memset_and_win64_preservation_required=True)


def inspect(data,bodies,assembly,ir,construction):
    caller,calls=check_caller(bodies,assembly)
    s.require(construction['function']==caller and
        construction['non_cshake_requires_zero_name_and_customization_lengths'] and
        construction['slot_equality_before_indexed_plan_read'], 'replayed actual start admission')
    return dict(caller=caller,incoming_references=incoming(data,caller),caller_paths=calls,
        helpers={str(bits):check_helper(bodies,ir,bits) for bits in NAMES},geometry=geometry(),
        empty_constructor_paths_qualified=True,inlined_cshake_constructors_qualified=False,
        retained_state_lifetime_composition_qualified=False,private_frame_erasure_qualified=False,
        shared_runtime_completion_package=8)
