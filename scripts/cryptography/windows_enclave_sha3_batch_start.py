"""Start admission and retained placement; constructor internals remain open."""
import re
import windows_enclave_sha3_batch_start_shapes as shapes

life,L=shapes.life,shapes.L
s=life.s
TABLES={'scalar':(46,[24,14,16,17,15,23,28,18]),'avx2':(44,[20,19,14,15,16,17,22,18])}


def slices(bodies,lane):
    n={k:s.one(bodies,'Owner'+str(len(k))+k+'$') for k in ('start','operation')}
    parts=dict(prefix=shapes.prefix(lane,n['operation']),reject=shapes.reject(lane),
        epilogue=shapes.epilogue(lane),zero_lengths=shapes.zero_lengths(lane),placement=shapes.placement(lane))
    labels=[14,16,17,15,23] if lane=='scalar' else [19,14,15,16,17]
    for tag,label in enumerate(labels,1):
        parts['identity_'+str(tag+1)]=L(f'.B{label}:|movb ${tag}, %al')
        if tag<5:parts['identity_'+str(tag+1)]+=L(f'jmp .B{24 if lane=="scalar" else 20}')
    return n,parts


def check_shapes(bodies,assembly,lane):
    s.require(lane in TABLES,'sequential constructor lane')
    n,expected=slices(bodies,lane);lines=life.code(bodies[n['start']]);covered=set()
    s.require(len(lines)==(1361 if lane=='scalar' else 597),'complete frozen start extent')
    labels=[l for l in lines if l.endswith(':')]
    s.require(len(set(labels))==len(labels),'unique start control-flow labels')
    for role,part in expected.items():
        at=0 if role=='prefix' else lines.index(part[0])
        s.require(lines[at:at+len(part)]==part,'complete start '+role+' instruction contract')
        covered.update(range(at,at+len(part)))
    number,targets=TABLES[lane];table=f'.LJTI{number}_0'
    found=re.findall(r'^'+re.escape(table)+r':\n((?:\s*\.long[^\n]+\n)+)',assembly,re.M)
    s.require(len(found)==1 and [re.sub(r'\s+','',l) for l in found[0].splitlines()]==[
        f'.long.LBB{number}_{v}-{table}' for v in targets],'identity-to-constructor branch table')
    # Re-entry would invalidate the straight-line prefix's index/guard argument.
    prefix_labels={l[:-1] for l in expected['prefix'] if l.endswith(':')}
    s.require(not any(l.startswith('j') and l.split()[-1] in prefix_labels
        for l in lines[len(expected['prefix']):]),'no later re-entry into admission')
    # All eight table targets must actually exist, although their internals are pending.
    s.require(all(f'.B{v}:' in labels for v in targets),'live constructor branch destinations')
    return n,expected,sorted(covered)


def select(nonempty,completed,slot):
    """Public eight-slot scan and comparison before any indexed plan load."""
    s.require(all(type(v) is int and 0<=v<256 for v in (nonempty,completed)) and
        type(slot) is int and 0<=slot<1<<64,'bounded selector inputs')
    index=0;found=True
    if not (nonempty&1) or completed&1:
        for index in range(1,7):
            if nonempty&(1<<index) and not completed&(1<<index):break
        else:
            index=7;found=bool(nonempty&128) and not bool(completed&128)
    admitted=found and slot==index
    return index if admitted else None


def geometry(lane):
    """Concrete start stack/home slots and retained destination coverage.

    Stack-to-page separation is a caller allocation precondition; this model
    does not turn stack offsets into proof of initialized constructor values.
    """
    a=life.LAYOUT[lane];scalar=lane=='scalar'
    # Win64 entry RSP is 8 mod16. Eight pushes preserve that congruence.
    frame=7192 if scalar else 4888
    cases=[]
    for entry in (8,24):  # both possible entry residues modulo32
        before=entry-64-frame;current=before if scalar else before&~31
        base=current if scalar else before+128
        homes=[base+v for v in ((7296,7304,7312) if scalar else (4864,4872,4880))]
        s.require(homes==[entry+40,entry+48,entry+56],'u128 high/custom halves in actual Win64 homes')
        s.require(current%a['align']==0,'aligned local frame')
        cases.append(dict(entry_mod32=entry,alignment_padding=before-current))
    if scalar:
        # Exact writes in B47; repeated byte sources agree in overlapping stores.
        fields=[(16,35,1),(17,'bpl',1),(18,64,1),(19,288,8),(25,294,8),
            (33,48,1),(34,'dil',1),(35,248,8),(41,254,8),(49,36,1),(50,40,1),
            (51,232,8),(57,238,8),(65,5861,200),(265,3240,168),(433,3072,168),
            (601,2904,168),(769,1296,40),(809,1248,40),(849,5661,200),
            (1049,'r15d',4),(1053,'r12b',1),(1054,'r14b',1),(1055,'bl',1),
            (1056,56,1),(1057,120,1),(1058,2800,64),(1122,2864,16),(1136,2878,16)]
        state=[16,1152];limit=7168
    else:
        fields=[(1216,'r12b',1),(1217,3945,943),(2160,'r14',8),(2168,576,32),(2200,608,8)]
        state=[1216,2208];limit=4888
    writes={};overlap=0
    for dest,source,width in fields:
        s.require(state[0]<=dest<dest+width<=state[1],'state writes stay in retained state')
        if isinstance(source,int):s.require(32<=source<source+width<=limit,'source inside private locals, not saved registers')
        for i in range(width):
            origin=source+i if isinstance(source,int) else (source,i)
            if dest+i in writes:
                s.require(writes[dest+i]==origin,'overlapping placements copy identical source bytes');overlap+=1
            writes[dest+i]=origin
    s.require(set(writes)==set(range(*state)),'complete physical state placement, without neighbouring fields')
    s.require(state[1]<=a['size'] and (state[1]<=a['output'] or a['output']+1024<=state[0]),
        'retained state does not overlap retained output')
    return dict(frame_bytes=frame,saved_gpr_bytes=64,saved_xmm6_bytes=16 if scalar else 0,
        home_offsets_from_entry=[40,48,56],alignment_cases=cases,state_span=state,
        placement_bytes=len(writes),same_source_overlap_bytes=overlap,
        destination_complete=True,constructor_source_initialization_qualified=False,
        stack_to_retained_page_separation_required=True,stack_copy_erasure_qualified=False)


def inspect(bodies,assembly,ir,lane,storage,transitions,receiver):
    n,expected,covered=check_shapes(bodies,assembly,lane);a=life.LAYOUT[lane]
    s.require(n['start']==receiver['functions']['start'] and n['operation']==transitions['functions']['operation'],
        'actual receiver-to-start and start-to-operation targets')
    s.require(transitions['checked_next_sequence'] and transitions['phase_match_before_admission'] and
        transitions['unfinished_guard_clears_and_quarantines'] and
        transitions['owner_layout']==a,'replayed exact admission/guard layout')
    s.require(storage['state_pointer_inside_owner'] and
        storage['state_destructor']['function']==life.DROP[lane] and
        storage['state_destructor']['typed_payload_cleanup_composed'],'actual typed state destruction')
    if lane=='avx2':s.require(transitions['authority_check_before_sequence_commit'],'AVX2 authority before operation success')
    owner=f'ptr noalias nofree noundef nonnull align {a["align"]} dereferenceable({a["size"]})'
    abi=life.reuse.abi(ir,n['start'])
    s.require('('+owner+' %0, i64 noundef %1, i64 noundef %2, i128 noundef %3, i128 noundef %4)' in abi and
        'noundef range(i8 -1, 7) i8 @' in abi,'complete start owner/sequence/slot/u128/status ABI')
    return dict(function=n['start'],instruction_slice_sizes={k:len(v) for k,v in expected.items()},
        reviewed_instruction_positions=covered,collecting_phase=1,successful_phase=2,
        first_nonempty_unfinished_slot_required=True,slot_equality_before_indexed_plan_read=True,
        index_half_open_range=[0,8],identity_range=[1,8],identity_table_targets=TABLES[lane][1],
        non_cshake_requires_zero_name_and_customization_lengths=True,
        successful_placement_destroys_previous_typed_state_first=True,
        successful_slot_and_phase_commit_after_state_copy=True,
        rejection_clears_output_bytes=1024,rejection_quarantines_authority=lane=='avx2',
        geometry=geometry(lane),entire_start_body_qualified=False,
        constructor_internals_and_value_lifetimes_qualified=False,
        all_unwind_paths_qualified=False,private_frame_erasure_qualified=False,whole_image_qualified=False)
