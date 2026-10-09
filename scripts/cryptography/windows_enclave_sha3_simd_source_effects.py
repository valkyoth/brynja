"""Paired source/length and guarded byte footprints; caller lifetimes pending."""
import re
import windows_enclave_sha3_simd_absorb_effects as previous
w,o,s,life,loop,m=previous.w,previous.o,previous.s,previous.life,previous.loop,previous.m
SLOTS=(*previous.SLOTS,968)
SITES={827,851}
PARTS=(0,1,2,3,4,6)
LOADS={669:(0,536,'message'),671:(8,544,'message_length'),
    673:(64,552,'custom'),675:(72,560,'custom_length'),677:(32,816,'name'),679:(40,760,'name_length')}
STABLE=(512,536,544,552,560,760,816)
MASK=(1<<64)-1


def input_root(code,states,at,key,trail=frozenset()):
    s.require(at in states and key in states[at] and (at,key) not in trail,'anchored input-root definition')
    trail=trail|{(at,key)};sites=states[at][key];s.require(sites,'nonvacuous input-root predecessors')
    for site in sites:
        if site==-1:
            s.require(key=='r8','only original executor input-array argument is an input root');continue
        op,args=o.instruction(code[site]);dest=f'{key}(%rbp)' if isinstance(key,int) else '%'+key
        s.require(op=='movq' and args[-1]==dest,'whole input root, not partial, offset or clobber')
        if args[0].startswith('%'):
            source=args[0][1:];s.require(source in o.REGS,'original full-width root register')
        else:
            match=re.fullmatch(r'(\d+)\(%rbp\)',args[0])
            s.require(match is not None and int(match[1]) in SLOTS,'tracked full input-root spill cell')
            source=int(match[1])
        input_root(code,states,site,source,trail)


def source_cells(code,edges,spans,states,lane):
    for at,(offset,slot,_) in LOADS.items():
        operand=(str(offset) if offset else '')+'(%r14,%r8)'
        s.require(code[at:at+2]==[f'movq {operand}, %rax',f'movq %rax, {slot}(%rbp)'],
            'actual paired descriptor field read and full-width saved cell')
        input_root(code,states,at,'r14')
        s.require(0<=112*lane+offset<112*lane+offset+8<=448,'descriptor field inside original four-lane array')
    seen=set()
    def observe(at,before):
        if at in LOADS:
            s.require(before['r8']==m.one('number',112*lane),'same bounded lane for every pointer and length load')
            seen.add(at)
    m.check_lane(code,edges,spans,lane,observe);s.require(seen==set(LOADS),'all six descriptor loads observed')
    for at,(lo,hi) in spans.items():
        if at in previous.NODES:
            s.require(all(hi<=slot or slot+8<=lo for slot in STABLE),'source and matching length cells survive every direct byte-loop store')
    return {slot:m.one(kind,0) for _,slot,kind in LOADS.values()}


def prefix_offset(code,part):
    s.require(type(part) is int and part in (0,1,3),'only three prefix-producing dispatch classes')
    s.require(code[719:732]==previous.absorb.shape.L('''.B103:|xorl %eax, %eax|cmpq $1, %rbx|
        setne %al|incq %rax|testq %rbx, %rbx|cmoveq %rbx, %rax|movl %eax, %esi|
        shll $4, %esi|orq %rax, %rsi|addq 512(%rbp), %rsi|movl $17, %eax|jmp .B111'''),
        'actual bounded three-prefix selection instructions')
    # EAX starts zero; SETNE then INC yields 1/2, CMOVE selects zero for part0.
    encoded=(int(part!=1)+1) if part else 0
    offset=(encoded<<4)|encoded
    s.require(offset=={0:0,1:17,3:34}[part] and offset+17<=51,'three nonoverlapping 17-byte encoding fields')
    return offset


def selected_source(code,initial,part,dispatch):
    s.require(part in PARTS and dispatch in (718,759),'actual source-producing part and dispatch')
    state=initial.copy()
    for at in range(714 if dispatch==718 else 753,dispatch):
        state=previous.transfer(code[at],state)
        # The full-width spill at this point records name length before dispatch.
        if at in (716,755):state[840]=m.operand(o.instruction(code[at])[1][0],state)
    target=previous.absorb.shape.TARGETS[part]
    s.require(target=={0:103,1:103,2:112,3:103,4:107,6:110}[part], 'source class follows the linked part table')
    if part in (0,1,3):
        offset=prefix_offset(code,part);state['rsi']=m.add(initial[512],m.one('number',offset));state['rax']=m.one('number',17)
        start=796
    else:start={2:798,4:760,6:793}[part]
    # These direct branches all meet the same source/length spill point.
    while start<798:
        line=code[start]
        if line=='jmp .B111':start=796;continue
        state=previous.transfer(line,state);op,args=o.instruction(line)
        if start==797:state[840]=m.operand(args[0],state)
        start+=1
    base,length=(m.add(initial[512],m.one('number',{0:0,1:17,3:34}[part])),m.one('number',17)) if part in (0,1,3) else {
        2:(initial[816],initial[760]),4:(initial[552],initial[560]),6:(initial[536],initial[544])}[part]
    s.require(state['rsi']==base and state[840]==length,'same selected source and its matching original length')
    state['r14']=m.one('bit_offset',0)
    return state,base,length


def guarded_reads(code,edges,spans,initial,base,length,n):
    state=initial.copy();calls=[]
    for at in range(798,852):
        before=state;state=previous.transfer(code[at],before,spans.get(at))
        if at==814:
            s.require(code[at]=='shrq $3, %r14' and before['r14']==m.one('bit_offset',0),
                'logical u64 bit offset divided by eight before indexing')
            state['r14']=m.one('byte_index',0)
        if at in (817,840):
            first=at==817;index=0 if first else 1;bound='rax' if first else 'rsi'
            s.require(code[at]=='jae .B207' and code[at-1]==('cmpq %rax, %r14' if first else 'movq 848(%rbp), %rcx') and
                code[816 if first else 837]==f'cmpq %{bound}, %r14' and before['r14']==m.one('byte_index',index) and
                before[bound]==length and edges[at]==[code.index('.B207:'),at+1],
                'unsigned guard compares current index with the matching source length')
        if at in (820,842):
            first=at==820
            s.require(code[at]==('leaq (%rax,%r14), %rdx' if first else 'addq %r14, %rdx') and
                before['rax' if first else 'rdx']==base and before['r14']==m.one('byte_index',0 if first else 1),
                'same guarded index added to the original selected source')
            state['rdx']=m.one('guarded_source_byte',0 if first else 1)
        if at in SITES:
            s.require(code[at]=='callq '+n['xor'] and before['rdx']==m.one('guarded_source_byte',0 if at==827 else 1),
                'actual XOR reads only the corresponding guarded source byte')
            calls.append(at)
    s.require(calls==[827,851],'both byte-read paths reached in the successful-path analysis')
    return dict(call_sites=calls,first_index_maximum=MASK>>3,second_index_maximum=(MASK>>3)+1,
        source_and_length_remain_paired=True,index_increment_cannot_wrap=True)


def byte_window(length,bit_offset):
    s.require(type(length) is int and 0<=length<=1024 and type(bit_offset) is int and 0<=bit_offset<=MASK,
        'receiver-bounded source length and arbitrary u64 offset')
    index=bit_offset>>3
    return [index if index<length else None,index+1 if index<length and index+1<length else None]


def inspect(bodies,assembly,caller,receiving,descriptors,absorbing,prior):
    n=previous.absorb.shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==absorbing['function']==prior['function']==n['executor'] and
        receiving['actual_bitstring_inputs_use_local_buffers_not_host_addresses'] and
        receiving['all_twelve_inputs_bounded_to_separate_1024_byte_worker_slots'] and
        descriptors['pointer_length_bits_and_last_preserved_on_success'] and descriptors['bounded_bit_count_maximum']==8192 and
        absorbing['readonly_bit_sources_and_two_byte_splits_checked'] and
        prior['all_four_destinations_within_original_lane_rate'] and prior['external_source_sites_pending']==[827,851] and
        not prior['pending_non_frame_store_sites'], 'replayed local input/descriptor, absorption and destination contracts')
    edges,_=o.reconcile.graph(code,assembly);spans,_,_=o.frame_writes(code,edges)
    states=w.definitions(code,edges,spans,SLOTS);previous.flow(code,edges,n)
    # Every suffix entry follows its guard; the exact absorption graph also
    # rules out foreign entries into the shared prefix/payload selection blocks.
    for at in range(799,852):
        s.require({p for p,ds in edges.items() if at in ds}=={at-1},'no entry after source selection or either read guard')
    rows=[]
    for lane in range(4):
        initial=previous.entry(code,edges,spans,states,lane,168)
        initial.update(source_cells(code,edges,spans,states,lane))
        for part in PARTS:
            for dispatch in (718,759):
                chosen,base,length=selected_source(code,initial,part,dispatch)
                guarded_reads(code,edges,spans,chosen,base,length,n)
                root,offset=next(iter(base));size=17 if part in (0,1,3) else 1024
                s.require(root=='workspace' and 3584+156*lane<=offset<offset+size<=3584+156*(lane+1) or
                    root in ('message','name','custom') and offset==0,'bounded source field or original local payload root')
                rows.append(dict(lane=lane,part=part,dispatch=dispatch,read_root=root,read_envelope=[offset,offset+size],
                    one_byte_reads=True,guarded_by_matching_length=True))
    pending=set(prior['pending_callee_effect_sites'])
    s.require(SITES<=pending and len(pending-SITES)==18,'exact remaining source call population')
    return dict(function=n['executor'],call_sites=sorted(SITES),source_cases=rows,
        original_input_array_root_and_lane_field_loads_checked=True,
        source_length_pairing_and_two_unsigned_read_guards_checked=True,full_u64_byte_index_increment_nonwrapping=True,
        direct_saved_source_cell_preservation_checked=True,
        pending_non_frame_store_sites=[],pending_callee_effect_sites=sorted(pending-SITES),
        caller_descriptor_payload_placement_nonoverlap_and_lifetimes_required=True,
        other_callee_effects_and_win64_nonvolatile_preservation_required=True,
        allocation_lifetimes_and_private_frame_exception_cleanup_qualified=False)
