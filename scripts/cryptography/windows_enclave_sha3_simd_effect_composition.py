"""Join the independently replayed executor footprints and original allocations.

This closes executor-level alias assumptions, not nested private stack effects,
OS unwind dispatch, or the final three-route private-frame assignment.
"""
import windows_enclave_sha3_simd_service_effects as service
import windows_enclave_sha3_simd_source_effects as source
s,o,life=service.s,service.o,service.life


def calls(code,stages):
    assigned={};effects=[]
    def add(site,kind,spans):
        s.require(type(site) is int and site not in assigned and code[site].startswith('callq '),
            'exactly one replayed effect assignment per actual executor call')
        assigned[site]=kind
        effects.extend(dict(site=site,space=space,write=list(span)) for space,span in spans)
    frame=stages['frame']
    for site in frame['runtime_frame_call_sites']:
        rows=[e for case in frame['runtime_effect_cases'] for e in case['effects']
            if e['helper']==code[site].removeprefix('callq ') and case['region'][0]<=site<case['region'][1]]
        s.require(rows,'actual framing helper has replayed bounded cases')
        add(site,'frame runtime',[('child',r['write']) for r in rows])
    for key,field in (('clear','parent_relative_effects'),('copy','parent_relative_effects')):
        for site in stages[key]['call_sites']:
            rows=[r for r in stages[key][field] if r['site']==site]
            s.require(rows,'each assigned clear/copy has a physical write footprint')
            add(site,key,[('parent',r['span'] if key=='clear' else r['write']) for r in rows])
    scalar=stages['scalar']
    for site in scalar['call_sites']:
        rows=[r for r in scalar['copy_parent_relative_effects'] if r['site']==site]
        spans=[r['write'] for r in rows]
        if site==1311:spans=[r['span'] for r in scalar['kernel_parent_relative_effects']]
        s.require(spans,'scalar copy/kernel has explicit original regions');add(site,'scalar',[('parent',v) for v in spans])
    for site in stages['squeeze']['call_sites']:
        add(site,'squeeze',[('parent',r['destination_envelope']) for r in stages['squeeze']['physical_copy_envelopes']])
    # The absorption check proves the exact byte destination is within the
    # selected lane's validated rate. A 168-byte envelope is conservative, not
    # permission for an implementation to write beyond its checked byte.
    for key in ('absorb','source'):
        for site in stages[key]['call_sites']:
            add(site,key,[('parent',[1856+200*i,2024+200*i]) for i in range(4)])
    transfer=stages['transfer']['physical_envelopes']
    for site in stages['transfer']['call_sites']:
        spans=[]
        if site==563:spans=[('parent',v) for v in transfer['destinations']]
        elif site in (570,573):spans=[('parent',v) for v in transfer['metadata_parent_ranges']]
        elif site in (1547,1559,1571,1583):
            lane=(1547,1559,1571,1583).index(site);spans=[('parent',transfer['destinations'][lane])]
        else:s.require(site in (54,1430),'only the two readonly validators have no transfer writes')
        add(site,'output',spans)
    for row in stages['services']['service_effects']:
        spans=[]
        for root,regions in row.get('write_roots',{}).items():
            s.require(root in ('authority','workspace'),'closed service memory-write roots')
            spans.extend((root if root=='authority' else 'parent',
                v if root=='authority' else [v[0]-64,v[1]-64]) for v in regions)
        add(row['site'],'service',spans)
    terminal=stages['services']['nonreturning_terminal']
    s.require(terminal['normal_return'] is False,'panic terminal is never a returning memory contract')
    add(terminal['site'],'nonreturning terminal',[])
    actual={at for at,line in enumerate(code) if line.startswith('callq ')}
    s.require(set(assigned)==actual and len(actual)==57,'complete actual executor call population, no unassigned effects')
    return assigned,effects


def separation(effects,allocations):
    objects=allocations['resident_objects'];parent=allocations['parent_rbp'];child=allocations['child_rbp']
    s.require(child-parent==-1200,'actual nested-frame coordinate relation')
    # These are immutable during the executor call. Control charges and health
    # bytes deliberately are NOT immutable. Reused numeric spill cells are
    # governed separately by their all-predecessor/phase-specific dataflow.
    protected=[objects['inputs'],objects['destinations'],objects['authority'],objects['owner'],
        objects['plan_widths'],objects['plan_tags'],objects['operation_flag'],
        [objects['executor'][0],objects['executor'][0]+8],
        [objects['control'][0],objects['control'][0]+16],
        [child+592,child+656]]
    protected += [[child+v,child+v+8] for v in (*source.STABLE,448,456,1104,1112,1120)]
    protected += allocations['worker_payload_slots']+[allocations['receiver_descriptors'],allocations['header']]
    for row in effects:
        a,b=row['write'];space=row['space']
        s.require(type(a) is int and type(b) is int and a<b,'nonempty bounded write envelope')
        if space=='authority':
            s.require((a,b) in ((0,8),(16,17)),'authority effects exclude callback pointer and kernel tag');continue
        s.require(space in ('parent','child'),'assigned physical allocation coordinate')
        shift=parent if space=='parent' else child;a+=shift;b+=shift
        s.require(all(b<=lo or hi<=a for lo,hi in protected),'indirect call effect excludes every original pointer and input allocation')
    return dict(protected_physical_ranges=protected,authority_immutable_ranges=[[8,16],[17,18]],
        conservative_effect_cases=len(effects))


def inspect(bodies,stages,allocations):
    n=o.reconcile.terminal.shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(allocations['original_payload_and_authority_allocations_joined'] and
        allocations['conditional_page_payload_frame_nonoverlap_checked'] and
        stages['services']['all_executor_call_site_footprints_assigned'],
        'replayed original allocation and complete footprint prerequisites')
    for stage in stages.values():
        s.require(stage['function']==n['executor'],'all replayed effects refer to the same actual executor')
    s.require(stages['absorb']['all_four_destinations_within_original_lane_rate'] and
        stages['source']['source_length_pairing_and_two_unsigned_read_guards_checked'],
        'byte absorption source and destination contracts before conservative envelopes')
    assigned,effects=calls(code,stages)
    separated=separation(effects,allocations['physical_allocations'])
    return dict(function=n['executor'],call_assignments={str(k):v for k,v in sorted(assigned.items())},
        effects=effects,separation=separated,all_57_executor_call_footprints_composed=True,
        indirect_call_writes_preserve_original_inputs_authority_and_descriptor_cells=True,
        directly_preserved_pointer_dataflow_composes_with_indirect_effects=True,
        nested_private_frame_effects_and_runtime_abi_required=True,
        final_three_route_private_frame_composition_complete=False,
        complete_private_frame_erasure_qualified=False)
