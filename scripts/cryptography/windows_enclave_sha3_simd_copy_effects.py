"""Two framing and eight vector copy footprints; lifetime closure stays open."""
import windows_enclave_sha3_simd_clear_effects as clear
import windows_enclave_sha3_simd_frame_effects as frame
w,o,s,life,loop=clear.w,clear.o,clear.s,clear.life,clear.loop
SLOTS=tuple(sorted(set(clear.SLOTS)|{728,736,752,960}))
FRAMING={224:(187,218,121),301:(264,295,138)}
# call -> load, comparison, branch, multiply, add, compacted group lane
GATHER={1084:(1076,1077,1078,1079,1080,0),1095:(1087,1088,1089,1090,1091,1),
    1108:(1100,1101,1102,1103,1104,2),1121:(1113,1114,1115,1116,1117,3)}
SCATTER={1147:(1139,1140,1142,1143,1144,0),1161:(1153,1154,1155,1156,1157,1),
    1185:(1177,1178,1179,1180,1181,2),1206:(1198,1199,1200,1201,1202,3)}
SITES=set(FRAMING)|set(GATHER)|set(SCATTER)


def dominates(edges,cut,sites):
    todo=[0];seen=set()
    while todo:
        at=todo.pop()
        if at in seen:continue
        seen.add(at);todo.extend(v for v in edges[at] if (at,v)!=cut)
    s.require(not (set(sites)&seen),'guard success edge dominates assigned copy calls')


def framing_lengths(code,states,site,begin,increment):
    s.require(states[site]['r8']=={increment} and code[increment]=='leal 1(%rbx), %r8d' and
        states[increment]['rbx']=={begin+1} and code[begin+1]=='subq %r8, %rbx' and
        states[begin+1]['rbx']=={begin} and code[begin]=='movl $16, %ebx',
        'full-width 16-minus-skip then zero-extending plus-one on every predecessor')
    skips=frame.encoding_skips(code,states,begin+1)
    lengths=[16-skip+1 for skip in skips]
    s.require(set(lengths)==set(range(2,10)),'bounded nonwrapping encoded prefix length')
    return sorted(lengths)


def framing_copies(code,edges,states):
    w.guarded_lane(code,edges,states);dominates(edges,(95,96),FRAMING)
    effects=[]
    for site,(begin,increment,field) in FRAMING.items():
        s.require(code[site]=='callq memcpy' and
            w.expression(code,states,site,'rcx')=={('workspace',3584+field,156)} and
            frame.frame_origins(code,states,site,'rdx')=={176},
            'actual memcpy with original lane field and original child-frame source')
        lengths=framing_lengths(code,states,site,begin,increment)
        for lane in range(4):
            for size in lengths:
                start=3584+156*lane+field
                s.require(field+size<=field+17<=156,'copy stays in its own encoding field')
                effects.append(dict(site=site,read_root='child_frame',read=[176,176+size],
                    write_root='workspace',write=[start,start+size],bytes=size))
    return effects


def exact_length(code,states,site,reg,low):
    defs=states[site][reg];s.require(defs,'nonvacuous vector copy extent')
    for at in defs:
        s.require(at>=0,'initialized copy extent on every predecessor')
        s.require(code[at] in (f'movl $200, %{low}',f'movq $200, %{reg}'),
            'exact positive full-width 200-byte copy extent')


def vector_copies(code,edges,states,callee):
    effects=[]
    for site,(load,cmp,branch,mul,add,lane) in (GATHER|SCATTER).items():
        gather=site in GATHER;index='rax' if gather else 'rbx';address='r8' if gather else 'rcx'
        group='rcx' if gather else 'r8'
        s.require(code[site]=='callq '+callee and code[load]==f'movq {176+8*lane}(%rbp), %{index}' and
            code[cmp]==f'cmpq ${4 if lane==0 else 3}, %{index}' and
            code[branch]==('jae .B227' if lane==0 else 'ja .B227') and
            code[mul]==f'imulq $200, %{index}, %{address}' and
            code[add]==f'addq 960(%rbp), %{address}',
            'actual copy, compacted-index load, unsigned bound and 200-byte state stride')
        # The first scatter has a flag-preserving source-pointer MOV between
        # CMP and JA; all other comparisons branch immediately.
        s.require(branch==cmp+1 or (branch==cmp+2 and code[cmp+1]=='movq 776(%rbp), %r8'),
            'no flags modification between selected-index comparison and branch')
        for at in range(load+1,site+1):
            s.require({p for p,ds in edges.items() if at in ds}=={at-1},'no entry past selected-copy guard')
        s.require(edges[branch]==[code.index('.B227:'),branch+1] and
            states[cmp][index]==states[mul][index]=={load} and
            states[add][address]=={mul} and states[site][address]=={add},
            'same guarded index and unmodified state address on every reaching path')
        s.require(loop.roots(code,states,add,960,slots=SLOTS)=={1920} and
            loop.roots(code,states,site,group,slots=SLOTS)=={2720+200*lane},
            'original state array and exact compacted group slot')
        exact_length(code,states,site,'rdx','edx');exact_length(code,states,site,'r9','r9d')
        for selected in range(4):
            state=[1920+200*selected,2120+200*selected];packed=[2720+200*lane,2920+200*lane]
            effects.append(dict(site=site,read_root='workspace',read=state if gather else packed,
                write_root='workspace',write=packed if gather else state,bytes=200))
    return effects


def physical_effects(effects,geometry,child_origin):
    s.require(effects and child_origin==-1200,'replayed original child/parent frame relation')
    objects=geometry['executor_entry_objects'];start,end=objects['workspace'];physical=[]
    # Also checks workspace geometry and separation from every other allocation.
    clear.separate([dict(site=e['site'],root='workspace',write_spans=[e['write']]) for e in effects],geometry)
    for effect in effects:
        size=effect['bytes'];read=effect['read'];write=effect['write']
        s.require(type(size) is int and 0<size<=200 and read[1]-read[0]==write[1]-write[0]==size and
            effect['write_root']=='workspace','matching positive read/write copy extents')
        if effect['read_root']=='workspace':
            s.require(0<=read[0]<read[1]<=end-start,'read stays inside original workspace')
            src=[start+v for v in read]
        else:
            s.require(effect['read_root']=='child_frame' and -128<=read[0]<read[1]<=1000,
                'read stays inside original allocated child frame')
            src=[child_origin+v for v in read]
            s.require(all(src[1]<=a or b<=src[0] for a,b in objects.values()),
                'child source excludes every simultaneous caller allocation')
        dst=[start+v for v in write]
        s.require(src[1]<=dst[0] or dst[1]<=src[0],'actual source and destination do not overlap')
        physical.append(dict(site=effect['site'],read=src,write=dst,bytes=size))
    return physical


def inspect(bodies,assembly,caller,framing,vector,frame_effects,previous):
    n=o.reconcile.terminal.shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==framing['function']==vector['function']==
        frame_effects['function']==previous['function']==n['executor'] and
        caller['helpers']['copy_wrapper_checks_equal_lengths'] and caller['helpers']['copy_leaf_length_limit']==1024 and
        framing['public_framing_fields_and_output_offsets_checked'] and
        vector['scatter_returns_each_group_lane_to_original_slot'] and
        frame_effects['bounded_frame_effects_exclude_live_pointer_cells_and_caller_objects'] and
        previous['original_all_predecessor_receivers_and_lengths_checked'] and not previous['pending_non_frame_store_sites'],
        'replayed complete copy helper, framing, compaction, frame and wipe prerequisites')
    geometry=o.reconcile.terminal.shape.reject.digest.geometry()
    s.require(caller['geometry']==geometry,'same original resident caller allocations')
    edges,_=o.reconcile.graph(code,assembly);spans,_,_=o.frame_writes(code,edges)
    states=w.definitions(code,edges,spans,SLOTS)
    effects=framing_copies(code,edges,states)+vector_copies(code,edges,states,caller['helpers']['functions']['copy'])
    physical=physical_effects(effects,geometry,frame_effects['child_frame_origin_in_parent'])
    pending=set(previous['pending_callee_effect_sites'])
    s.require(SITES<=pending and len(pending-SITES)==27,'exact remaining copy-effect population')
    return dict(function=n['executor'],call_sites=sorted(SITES),copy_cases=effects,parent_relative_effects=physical,
        framing_length_range=[2,9],vector_copy_bytes=200,selected_lane_range=[0,3],
        original_source_destination_and_length_definitions_checked=True,
        all_copy_ranges_bounded_and_physically_nonoverlapping=True,
        pending_non_frame_store_sites=[],pending_callee_effect_sites=sorted(pending-SITES),
        runtime_memcpy_and_win64_nonvolatile_abi_required=True,
        other_callee_memory_effects_and_pointer_preservation_required=True,
        allocation_lifetimes_and_private_frame_exception_cleanup_qualified=False)
