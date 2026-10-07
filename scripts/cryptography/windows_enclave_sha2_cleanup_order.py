"""Join descriptor destruction to the actual preceding FH3 handler effects.

This covers the caller-side handler prefix and its saved pointer lifetimes.
Normal helper effects and OS/ABI stack dispatch remain separate obligations.
"""
import windows_enclave_sha2_cleanup_invokes as invokes
import windows_enclave_sha2_simd_storage as storage
import windows_enclave_sha2_effect_placement as placement
n,o,s=invokes.n,invokes.o,invokes.s


def prefix(bodies,name,expected,output=None):
    lines=s.lines(bodies[name]);end=(o.unique(lines,'callq '+output) if output else
        lines.index('.seh_startepilogue'))
    begin=o.unique(lines,'.seh_endprologue')+1
    actual=[v for v in lines[begin:end] if not v.startswith('.') and not v.endswith(':')]
    s.require(actual==expected,'complete cleanup prefix has only assigned reads/writes/calls')
    # Frame reconstruction must not smuggle an extra write or arbitrary branch
    # before the body. Shared OS dispatch supplies the original establisher.
    prologue=[v for v in lines[:begin] if not v.startswith('.') and not v.endswith(':')]
    registers=('rbp','r15','r14','r13','r12','rsi','rdi','rbx')
    allocation=56 if 'sha512_simd_resident' in name else 40
    s.require(prologue==['movq %rdx, 16(%rsp)']+['pushq %'+v for v in registers]+[
        f'subq ${allocation}, %rsp','leaq 128(%rdx), %rbp'],
        'exact cleanup frame reconstruction before its assigned effects')
    return dict(first=begin,last=end,assigned_instructions=len(actual))


def disjoint(effects,regions):
    s.require(effects and regions,'nonvacuous cleanup write/descriptor composition')
    for root,lo,hi in effects:
        s.require(root in ('resident-frame','resident-page') and
            type(lo) is int and type(hi) is int and lo<hi,'assigned cleanup write extent')
        if root=='resident-frame':
            s.require(all(not placement.cells.overlaps((lo,hi),span) for span in regions),
                      'earlier handler writes preserve every live descriptor and guard flag')


def wide_slots(bodies,assembly,rows,selected):
    name=s.one(bodies,r'Executor13digest_secret$');lines=s.lines(bodies[name])
    tables=o.source.paths.jump_tables(assembly,lines)
    initial=o.definitions(lines,name,tables,slots=(1024,1048))
    states=o.definitions(lines,name,tables,slots=(1024,1048),indexed=o.indexed_effects(lines,initial,tables))
    load=o.unique(lines,'.B4:')+1;save=o.unique(lines,'.Ltmp36:')+1
    s.require(lines[load]=='movq (%r15), %rax' and lines[save]=='movq %rax, 1024(%rbp)',
              'original authority field and its first-invoke save')
    checked=[]
    for row in rows:
        at=row['call']
        if not row['handlers']:continue
        s.require(states[at][1168]=={-1},'original incoming workspace remains live for cleanup')
        o.require_origin(lines,states,at,1048,'executor',0,{1048:('executor',0)})
        if selected in row['preceding_handlers']:
            s.require(states[at][1024]=={save} and states[save]['rax']=={load},
                      'earlier quarantine handler has its original saved authority')
            o.require_origin(lines,states,load,'r15','executor',0,{1048:('executor',0)})
        checked.append(at)
    s.require(len(checked)==10,'all ten child protected-call pointer lifetimes')
    return checked


def chains(bodies,assembly,lane,name,review,allowed):
    tables=invokes.authority.cleanup_tables(assembly,bodies,lane)
    ordered=tables['parents'][name]['ordered_handlers_from_ip'];active=[];rows=[]
    calls={row['call']:row['handlers'] for row in review['calls']}
    for at,line in enumerate(s.lines(bodies[name])):
        if line.endswith(':') and line[:-1] in ordered:active=ordered[line[:-1]]
        if at not in calls:continue
        s.require(line.startswith('callq '),'descriptor requirement still names an actual protected call')
        selected=[v for v in active if v in review['handlers']]
        s.require(selected==calls[at],'same descriptor requirements and current ordered FH3 chain')
        before=[]
        for handler in selected:
            earlier=active[:active.index(handler)]
            s.require(all(h in allowed for h in earlier),'every preceding cleanup handler has an effect assignment')
            before.extend(earlier)
        rows.append(dict(call=at,handlers=selected,preceding_handlers=before))
    s.require(len(rows)==len(calls),'all protected callsites included in cleanup ordering')
    return rows


def inspect(bodies,assembly,lane,prior):
    narrow=lane=='simd256';s.require(lane in ('simd256','simd512'),'assigned cleanup composition route')
    descriptors=prior['simd_dynamic_clearing_descriptors'];physical=prior['simd_physical_allocation_lifetimes']
    s.require(descriptors['normal_direct_descriptor_write_lifetimes_checked'] is True and
        descriptors['exact_pointer_length_pair_and_all_loop_indices_checked'] is True and
        physical['conditional_physical_separation'] is True and
        physical['constructor_result_and_worker_use_joined'] is True and
        prior['simd_metadata_preservation']['conditional_input_and_authority_field_preservation_checked'] is True,
        'cleanup order requires current descriptor and physical lifetime checks')
    storage.wiping(bodies,lane);names=storage.symbols(bodies)
    invoked=invokes.authority.digest_handlers(bodies,lane)
    name=descriptors['function'];review=descriptors['unwind_requirements']
    stem='Resident6digest' if narrow else 'Executor13digest_secret'
    def handler(number):return s.one(bodies,r'^\?dtor\$'+str(number)+r'@.*'+stem+r'@4HA$')
    earlier=[handler(v) for v in ((275,276) if narrow else (303,))]
    target=handler(277 if narrow else 304);output=names['output'];checks={}
    expected_handlers={target,handler(272)} if narrow else {target}
    s.require(set(review['handlers'])==expected_handlers and
        descriptors['descriptor_regions']==([[864,992],[2912,3040]] if narrow else [[816,880]]),
        'exact original/returned descriptor and destructor population')
    frame=['andq $-32, %rdx','movq %rdx, %rbx'] if narrow else []
    authority_slot='88(%rbx)' if narrow else '1024(%rbp)'
    for h in earlier:
        checks[h]=prefix(bodies,h,frame+[f'movq {authority_slot}, %rax','movb $0, 16(%rax)'])
    if narrow:
        body=frame+['leaq 6688(%rbx), %rcx','callq '+names['workspace'],
            'movq 88(%rbx), %rax','movb $0, 16(%rax)','leaq 864(%rbx), %rcx']
        effects=[('resident-frame',6688,11968),('resident-page',16,17)]
        regions=descriptors['descriptor_regions']+[[71,72]]
        checks[handler(272)]=prefix(bodies,handler(272),frame+[
            'cmpb $0, 71(%rbx)','je .B274','leaq 2912(%rbx), %rcx'],output)
    else:
        body=['movq 1168(%rbp), %rcx','callq '+names['workspace'],
            'movq 1048(%rbp), %rax','movb $1, 16(%rax)','movq (%rax), %rax',
            'testq %rax, %rax','je .B306','movb $0, 16(%rax)','leaq 816(%rbp), %rcx']
        effects=[('resident-frame',7200,12960),('resident-frame',136,137),('resident-page',16,17)]
        layout=placement.placements(bodies,lane)
        regions=[placement.place(dict(object='frame',span=v),layout)['span']
                 for v in descriptors['descriptor_regions']]
    checks[target]=prefix(bodies,target,body,output)
    s.require(set(checks)<=set(invoked),'all assigned prefixes are bound invoked handlers')
    disjoint(effects,regions)
    rows=chains(bodies,assembly,lane,name,review,set(earlier))
    if narrow:
        pointers=prior['simd_narrow_pointer_lifetimes']['unwind_pointer_lifetimes']
        s.require(pointers['original_saved_pointers_available_at_all_invoke_calls'] is True,
                  'narrow authority slot remains valid at every cleanup boundary')
        known={v['call']:v for v in pointers['callsite_lifetimes']}
        s.require(all(row['call'] in known and (target not in row['handlers'] or
            88 in known[row['call']]['required_pointer_slots']) for row in rows),
            'descriptor boundaries joined to authority availability')
        checked=[row['call'] for row in rows if row['handlers']]
    else:checked=wide_slots(bodies,assembly,rows,earlier[0])
    extra=[]
    if not narrow:
        handoff=prior['simd_wide_descriptor_handoff']
        s.require(handoff['conditional_direct_descriptor_handoff_checked'] is True,
                  'parent output availability comes from the checked returned descriptor')
        parent=handoff['parent'];parent_review=parent['unwind_requirements']
        parent_handler=s.one(bodies,r'^\?dtor\$91@.*Resident6digest@4HA$')
        s.require(set(parent_review['handlers'])=={parent_handler},'exact parent descriptor destructor')
        checks[parent_handler]=prefix(bodies,parent_handler,[
            'andq $-32, %rdx','movq %rdx, %rbx','cmpb $0, 55(%rbx)',
            'je .B93','leaq 352(%rbx), %rcx'],output)
        extra=chains(bodies,assembly,lane,parent['function'],parent_review,set())
        s.require(sum(bool(row['handlers']) for row in extra)==2,'both parent cleanup boundaries have no earlier handlers')
    return dict(function=name,handler_prefixes=checks,write_envelopes=[list(v) for v in effects],
        protected_regions=regions,ordered_calls=rows,parent_ordered_calls=extra,
        pointer_lifetime_calls=checked,protected_boundaries=len(checked)+sum(bool(v['handlers']) for v in extra),
        prior_handler_and_pre_drop_effects_conditionally_disjoint=True,
        normal_helper_effect_composition_pending=True,
        shared_prerequisites=physical['prerequisites'],
        OS_dispatch_and_handler_stack_preservation_required=True,whole_frame_qualified=False)
