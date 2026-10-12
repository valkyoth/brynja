"""Finite normal-path RSP/save-stack analysis over actual decoded instructions.

Both possible Win64 entry residues modulo 32 are checked. This is stack/control
geometry, not payload alias analysis or an exception unwinder. Named callees
and imported effects are composed separately; no unknown call gets zero depth.
"""
import re
import windows_enclave_stack_decode as decode

require=decode.require
SAVED={'rbx','rbp','rsi','rdi','r12','r13','r14','r15'}


def height(chunks):return -sum(v[1] for v in chunks)


def release(chunks,target):
    while height(chunks)<target:
        require(chunks and chunks[-1][0]=='local','release only owned locals, not saved registers')
        chunks=chunks[:-1]
    require(height(chunks)==target,'exact live allocation boundary')
    return chunks


def capacity(chunks):
    amount=0
    for kind,size,_ in reversed(chunks):
        if kind!='local':break
        amount+=size
    return amount


def scan(code,rva,table_targets,probe_targets,entry_residue):
    require(entry_residue in (8,24),'both Win64 entry residues are explicit')
    edges,transfers=decode.graph(code,rva,table_targets)
    todo=[(0,(),None)];states={};calls={};returns=[];traps=[];low=0;alignments=[]
    while todo:
        at,chunks,bp=todo.pop();state=(chunks,bp)
        if at in states:
            old_chunks,old_bp=states[at]
            require(old_chunks==chunks,'stable stack state at loop/branch join')
            bp=bp if bp==old_bp else None
            if bp==old_bp:continue
            state=(chunks,bp)
        require(at in code,'bounded reachable instruction');states[at]=state
        raw,text=code[at];op,_,operand=text.partition(' ');sp=height(chunks);low=min(low,sp)
        args=operand.split(', ')
        if op=='pushq':
            register=operand.removeprefix('%')
            require(register in SAVED,'only matched nonvolatile pushes')
            chunks+=('save',8,register),
        elif op=='popq':
            register=operand.removeprefix('%')
            require(chunks and chunks[-1]==('save',8,register),'matched nonvolatile pop')
            chunks=chunks[:-1]
            if register=='rbp':bp=None
        elif op in ('subq','addq') and args[-1]=='%rsp':
            if operand=='%rax, %rsp' and op=='subq':
                before=[p for p,(b,_) in code.items() if p+len(b)==at]
                require(len(before)==1,'unique immediately preceding stack probe')
                site=before[0];transfer=transfers.get(site,{})
                require(transfer.get('target') in probe_targets and transfer.get('kind')=='call',
                    'actual named stack probe preserves constant RAX')
                mov=code.get(site-5)
                require(mov is not None and len(mov[0])==5 and mov[0][0]==0xb8,'immediate EAX probe request')
                size=int.from_bytes(mov[0][1:],'little')
            else:
                match=re.fullmatch(r'\$((?:0x)?[0-9a-f]+), %rsp',operand)
                require(match is not None,'no unbounded stack adjustment');size=int(match[1],0)
            require(0<size<65536,'bounded positive stack adjustment')
            chunks=chunks+(('local',size,''),) if op=='subq' else release(chunks,sp+size)
        elif op=='andq' and args[-1]=='%rsp':
            require(operand=='$-0x20, %rsp' and bp is not None,'only restored 32-byte alignment')
            size=(entry_residue+sp)%32
            if size:chunks+=(('local',size,''),)
            alignments.append(dict(at=at,padding=size))
        elif op=='leaq' and args[-1] in ('%rsp','%rbp'):
            match=re.fullmatch(r'(0x[0-9a-f]+)?\(%(rsp|rbp)\), %(rsp|rbp)',operand)
            if args[-1]=='%rbp' and (match is None or match[2]!='rsp'):
                bp=None
            elif args[-1]=='%rbp':
                offset=int(match[1] or '0',0)
                require(any(v==('save',8,'rbp') for v in chunks),'saved frame-base setup')
                bp=sp+offset
            else:
                require(match is not None,'bounded frame-base instruction')
                offset=int(match[1] or '0',0)
                require(match[2]=='rbp' and bp is not None,'known original frame base')
                chunks=release(chunks,bp+offset)
        elif at in transfers:
            transfer=transfers[at]
            if transfer['kind']=='tail':
                require(not chunks and sp==0,'tail transfer after full stack restoration')
                calls[at]=transfer|dict(entry_offset=0,home_bytes_required=32,
                    allocated_outgoing_bytes=None)
            elif transfer['target'] in probe_targets:
                # __chkstk's private interface does not require Win64 home or
                # alignment. It saves exactly R10/R11 below its return address.
                calls[at]=transfer|dict(entry_offset=sp-8,home_bytes_required=0,probe=True,
                    allocated_outgoing_bytes=capacity(chunks))
            else:
                require((entry_residue+sp)%16==0 and capacity(chunks)>=32,
                    'aligned call with owned 32-byte home')
                calls[at]=transfer|dict(entry_offset=sp-8,home_bytes_required=32,
                    allocated_outgoing_bytes=capacity(chunks))
        elif op=='retq':
            require(not chunks and sp==0,'balanced stack on every normal return');returns.append(at)
        elif op in ('ud2','int3'):traps.append(at)
        else:
            require(not op.startswith(('push','pop','enter','leave')),'no unassigned implicit stack change')
            require(not (op.startswith(('xchg','xadd')) and
                re.search(r'%(?:rsp|esp|sp|spl)\b',operand)),
                'no two-destination stack-pointer exchange')
            # AT&T destination-last; comparisons do not write their operands.
            if args and args[-1] in ('%rsp','%esp','%sp','%spl'):
                require(op.startswith(('cmp','test')),'no unassigned RSP write')
            if args and args[-1] in ('%rbp','%ebp','%bp','%bpl') and not op.startswith(('cmp','test')):
                bp=None
        low=min(low,height(chunks))
        require(-65536<low<=0,'bounded local normal-path stack')
        todo.extend((to,chunks,bp) for to in edges[at])
    require(returns or traps or any(v['kind']=='tail' for v in calls.values()),'explicit reachable exits')
    return dict(local_low=low,calls=[dict(site=k,**v) for k,v in sorted(calls.items())],
        normal_returns=sorted(returns),terminal_traps=sorted(traps),alignment=alignments,
        reachable_instructions=len(states),entry_residue=entry_residue)


def inspect(code,rva,table_targets,probe_targets):
    return [scan(code,rva,table_targets,probe_targets,residue) for residue in (8,24)]


def leaf_accesses(name,code,scans):
    """No absent unwind record is itself a zero-footprint proof.

    Only this population's exact read of argument five is permitted. This does
    not prove arbitrary pointer aliases or general nonleaf argument lifetimes.
    Tail callees are composed later, not erased by the leaf classification.
    """
    require(all(v['local_low']==0 and all(c['kind']=='tail' for c in v['calls'])
        for v in scans),'metadata-less body has no allocation or nested CALL')
    reads=[]
    for at,(raw,text) in code.items():
        if not re.search(r'%(?:rsp|esp|sp|spl)\b',text):continue
        require(name.endswith('17secret_memory_xor8xor_bits') and
            text=='movl 0x28(%rsp), %r11d' and raw==bytes.fromhex('448b5c2428'),
            'only bound fifth-argument read in metadata-less leaves')
        reads.append(dict(site=at,entry_span=[40,44],write=False))
    return dict(explicit_stack_accesses=reads,incoming_bytes=36 if reads else 32,
        own_stack_bytes=0,tail_descendants_not_inferred=True)
