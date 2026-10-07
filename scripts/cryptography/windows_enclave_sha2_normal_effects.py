"""Join reviewed normal call effects to live SIMD descriptor allocations.

This is a finite, partial callsite composition, not a whole-function claim.
Unassigned calls remain explicit, including the wide parent. Private stack
bounds and original argument lifetimes are separate required inputs.
"""
import windows_enclave_sha2_effect_placement as p
import windows_enclave_sha2_simd_storage as storage
import windows_enclave_sha2_callee_stack as stack
import windows_enclave_sha2_wide_result as result
n,o,s=result.n,result.o,result.s


def bind_calls(lines,calls,offset=0):
    rows=[];seen=set()
    for call in calls:
        at=call['line']+offset
        s.require(type(call['line']) is int and 0<=at<len(lines) and at not in seen and
                  lines[at]=='callq '+call['target'],'unique current normal callsite and target')
        seen.add(at);rows.append(call|dict(line=at))
    return rows


def footprints(call):
    if 'footprints' in call:
        s.require('reads' not in call and 'writes' not in call,'one unambiguous effect representation')
        return [(direction,dict(object=obj,span=[lo,hi])) for direction,obj,lo,hi in call['footprints']]
    s.require('reads' in call and 'writes' in call,'explicit read and write contracts, even when empty')
    return [(direction,region) for direction in ('reads','writes') for region in call[direction]]


def exclude(effects,protected,layout):
    mapped=set()
    s.require(protected,'nonempty protected descriptor population')
    for direction,region in effects:
        s.require(direction in ('reads','writes'),'assigned normal effect direction')
        placed=p.place(region,layout)
        if direction=='writes':
            s.require(all(placed['root']!=v['root'] or not p.cells.overlaps(placed['span'],v['span'])
                          for v in protected),'normal helper writes exclude every live descriptor')
        mapped.add((direction,placed['root'],*placed['span']))
    return [list(v) for v in sorted(mapped)]


def stack_exclude(span,protected,origin=0):
    s.require(len(span)==2 and all(type(v) is int for v in span) and span[0]<span[1],
              'nonempty reviewed normal stack span')
    actual=[v+origin for v in span]
    s.require(all(v['root']!='resident-frame' or not p.cells.overlaps(actual,v['span']) for v in protected),
              'normal callee stacks and ABI home exclude every descriptor')
    return actual


def wipe_calls(bodies,assembly,lane,parent=False):
    names=storage.symbols(bodies);wide=lane=='simd512'
    name=names['resident'] if parent or not wide else s.one(bodies,r'Executor13digest_secret$')
    lines=s.lines(bodies[name]);tables=o.source.paths.jump_tables(assembly,lines)
    edges=result.d.graph(lines,assembly);targets={names['workspace'],names['drop']}
    sites=[at for at,line in enumerate(lines) if line.startswith('callq ') and line[6:] in targets]
    s.require(len(sites)==(2 if parent else 4 if wide else 6),'complete workspace wipe/drop call population')
    if parent:result.fixed_parent_frame(lines,edges)
    elif not wide:n.prepare(lines,assembly,name)
    else:
        raw=o.definitions(lines,name,tables)
        states=o.definitions(lines,name,tables,indexed=o.indexed_effects(lines,raw,tables))
    rows=[]
    for at in sites:
        first=at-2 if lines[at-1]=='vzeroupper' else at-1
        if wide and not parent:
            s.require(lines[first]=='movq %rdi, %rcx','wipe receives the current workspace pointer')
            o.require_workspace(lines,states,first,'rdi',0,{})
        else:
            s.require(lines[first]==f'leaq {7200 if wide else 6688}(%rbx), %rcx',
                      'wipe receives the actual original resident workspace')
        n.straight(edges,first,at)
        rows.append(dict(line=at,target=lines[at][6:],role='workspace_drop' if lines[at][6:]==names['drop']
            else 'workspace_wipe',footprints=[['writes','frame',6688,11968]] if not wide else
            [['writes','workspace',0,5760]]))
    # Recheck the entire destructor bodies, not just symbol names or envelopes.
    storage.wiping(bodies,lane)
    frames={};todo=list(targets)
    while todo:
        callee=todo.pop()
        if callee in frames:continue
        proof=stack.inspect_body(bodies[callee],callee,set(bodies),{})
        frames[callee]=proof;todo.extend(v[1] for v in proof['calls']+proof['tail_calls'])
    s.require(len(frames)==5,'workspace/drop/scalar/cpu/zeroizer normal stack closure')
    sp=-128 if wide and not parent else 0
    extent=[sp-8+min(stack.depth(v,frames) for v in targets),sp]
    return dict(function=name,calls=rows,stack_span=extent,normal_callee_count=len(frames))


def inventory(lines,assigned):
    actual=[dict(line=at,target=line[6:]) for at,line in enumerate(lines) if line.startswith('callq ')]
    keys=[(v['line'],v['target']) for v in assigned]
    s.require(len(keys)==len(set(keys)) and set(keys)<={(v['line'],v['target']) for v in actual},
              'no duplicate, stale or invented call assignment')
    return [v for v in actual if (v['line'],v['target']) not in set(keys)]


def inspect(bodies,assembly,lane,prior):
    narrow=lane=='simd256';s.require(lane in ('simd256','simd512'),'assigned normal composition lane')
    descriptors=prior['simd_dynamic_clearing_descriptors'];physical=prior['simd_physical_allocation_lifetimes']
    s.require(descriptors['normal_direct_descriptor_write_lifetimes_checked'] is True and
        descriptors['exact_pointer_length_pair_and_all_loop_indices_checked'] is True and
        physical['conditional_physical_separation'] is True and
        physical['constructor_result_and_worker_use_joined'] is True and
        prior['simd_metadata_preservation']['conditional_input_and_authority_field_preservation_checked'] is True,
        'current descriptor, input, allocation and authority prerequisites')
    lifetime=prior['simd_narrow_pointer_lifetimes' if narrow else 'simd_helper_slot_origins']
    s.require(lifetime['normal_cfg_pointer_definition_lifetimes_checked' if narrow else
                       'direct_cfg_origins_and_preservation_checked'] is True,
              'normal effects require the original pointer definitions and preserved slots')
    frame=prior['simd_first_output_frame_cell'];name=frame['function'];lines=s.lines(bodies[name])
    s.require(name==descriptors['function'],'same descriptor and finish function')
    layout=p.placements(bodies,lane);protected=[p.place(dict(object='frame',span=span),layout)
                                             for span in descriptors['descriptor_regions']]
    if not narrow:
        handoff=prior['simd_wide_descriptor_handoff']
        s.require(handoff['conditional_direct_descriptor_handoff_checked'] is True,'current wide parent handoff')
        parent=handoff['parent']
        s.require(parent['original_descriptor_argument']==[352,416] and parent['returned_descriptors']==[4640,4704],
                  'exact parent descriptor regions')
        protected += [dict(root='resident-frame',span=parent[key]) for key in
                      ('original_descriptor_argument','returned_descriptors')]
    primitive,transfer,control=[prior['simd_'+key+'_call_effects'] for key in ('scalar','transfer','control')]
    calls,terminal,_=p.collect(frame,primitive,transfer,control)
    offset=lines.index(frame['begin']+':')
    assigned=bind_calls(lines,calls,offset);terminals=bind_calls(lines,terminal,offset)
    s.require(len(assigned)==(17 if narrow else 18),'complete selected finish returning-call population')
    # Narrow padding reuses bytes 2928..2936 as control counters before the
    # returned descriptor is constructed there. Byte nonoverlap alone would
    # reject valid storage reuse. Prove no path from construction returns to
    # these calls; an earlier instruction number alone is not a lifetime proof.
    edges=result.d.graph(lines,assembly);before_returned=[];mapped=[]
    returned_reachable=(n.g.reachable(edges,descriptors['copies'][0]['last_line']) if narrow else set())
    for call in assigned:
        live=protected
        if narrow and call['line'] not in returned_reachable:
            live=protected[:1];before_returned.append(call['line'])
        mapped+=exclude(footprints(call),live,layout)
    stores=frame['conditional_indirect_store_effects']['stores']
    mapped+=exclude([('writes',dict(object=v['object'],span=v['span'])) for v in stores],protected,layout)
    spans=[];tracked=prior['simd_tracked_callee_stack']
    s.require(tracked['normal_private_stack_effects_exclude_saved_pointer'] is True and
              tracked['tracked_returning_call_sites']==len(assigned),'current finish stack proof')
    spans.append(stack_exclude(tracked['caller_frame_relative_stack_span'],protected,layout['frame']['offset']))
    home=[0,32] if narrow else [-128,-96]
    spans.append(stack_exclude(home,protected,layout['frame']['offset']))
    if not narrow:
        earlier=prior['simd_earlier_call_effects'];vector=prior['simd_vector_callee_stack']
        s.require(earlier['conditional_argument_effects_and_reviewed_stacks_disjoint'] is True and
                  vector['normal_stack_effects_disjoint'] is True,'current early argument and stack reviews')
        early=bind_calls(lines,earlier['calls']);s.require(len(early)==6,'all six earlier calls')
        mapped+=exclude([effect for call in early for effect in footprints(call)],protected,layout)
        assigned+=early
        spans.append(stack_exclude(vector['caller_frame_relative_stack_span'],protected,layout['frame']['offset']))
    wipes=wipe_calls(bodies,assembly,lane)
    s.require(wipes['function']==name,'same workspace callsite function')
    assigned+=bind_calls(lines,wipes['calls'])
    mapped+=exclude([effect for call in wipes['calls'] for effect in footprints(call)],protected,layout)
    spans.append(stack_exclude(wipes['stack_span'],protected,layout['frame']['offset']))
    pending=inventory(lines,assigned+terminals);parent_review=None
    if not narrow:
        parent_wipes=wipe_calls(bodies,assembly,lane,True);parent_lines=s.lines(bodies[parent_wipes['function']])
        parent_calls=bind_calls(parent_lines,parent_wipes['calls'])
        mapped+=exclude([effect for call in parent_calls for effect in footprints(call)],protected,layout)
        spans.append(stack_exclude(parent_wipes['stack_span'],protected))
        spans.append(stack_exclude([0,32],protected))
        parent_review=dict(function=parent_wipes['function'],assigned=parent_calls,
                           pending=inventory(parent_lines,parent_calls))
    return dict(function=name,protected_descriptors=protected,assigned=sorted(assigned,key=lambda v:v['line']),
        assigned_returning_calls=len(assigned),terminal_calls=terminals,unassigned_calls=pending,
        calls_unreachable_after_returned_descriptor_construction=before_returned,
        mapped_effects=[list(v) for v in sorted({tuple(v) for v in mapped})],normal_stack_spans=spans,
        workspace_calls=wipes['calls'],parent=parent_review,
        selected_normal_helpers_conditionally_preserve_descriptors=True,
        workspace_wipe_original_arguments_and_normal_stacks_checked=True,
        all_normal_calls_composed=False,remaining_calls_and_final_frame_assignments_pending=True,
        shared_prerequisites=physical['prerequisites'],whole_frame_qualified=False)
