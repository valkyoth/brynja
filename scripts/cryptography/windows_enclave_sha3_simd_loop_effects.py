"""Last executor stores: bounded readiness/cursor writes, not lifetime closure."""
import re
import windows_enclave_sha3_simd_loop_effects_model as model
w,o,s=model.workspace,model.o,model.s
life=w.life
CLEARS={1231:(1224,1225,1226),1235:(1232,1233,1234),
    1242:(1238,1239,1240),1249:(1245,1246,1247)}
SITES=set(model.STORES)|{619}|set(CLEARS)


def roots(code,states,at,key,trail=frozenset()):
    s.require(at in states and key in states[at] and (at,key) not in trail,'anchored full-width workspace root')
    trail=trail|{(at,key)};result=set()
    for site in states[at][key]:
        if site==-1:
            s.require(key==1104,'original incoming workspace root only');result.add(0);continue
        op,args=o.instruction(code[site]);dest=f'{key}(%rbp)' if isinstance(key,int) else '%'+key
        s.require(args and args[-1]==dest,'full-width exact root definition, not overlapping or ABI clobber')
        if op=='movq':
            src=args[0]
            if src.startswith('%') and src[1:] in o.REGS:other=src[1:]
            else:
                m=re.fullmatch(r'(\d+)\(%rbp\)',src)
                s.require(m is not None and int(m[1]) in model.SLOTS,'tracked original pointer cell')
                other=int(m[1])
            result.update(roots(code,states,site,other,trail))
        elif op=='leaq':
            m=re.fullmatch(r'(-?\d*)\(%(\w+)\)',args[0])
            s.require(m is not None,'constant displacement from original workspace')
            result.update(x+int(m[1] or 0) for x in roots(code,states,site,m[2],trail))
        else:s.require(False,'unknown workspace-root producer: '+op)
    s.require(result,'nonvacuous original workspace origins');return result


def loop_entry(code,edges,states):
    incoming={(at,v) for at,ds in edges.items() for v in ds if at not in model.NODES and v in model.NODES}
    s.require(incoming=={(623,642)},'one original entry into the complete per-lane CFG')
    s.require(code[620:624]==['movq %rsi, %rdx','xorl %r8d, %r8d','xorl %r9d, %r9d','jmp .B92'] and
        code[637:643]==['addq $112, %r8','incq %r9','addq $156, %rdx','cmpq $448, %r8','je .B131','.B92:'] and
        edges[641]==[992,642], 'exact initial lane, synchronized increments and fourth-lane exit')
    for at in (621,622,623):
        s.require({p for p,ds in edges.items() if at in ds}=={at-1},'no bypass of initial lane setup')
    s.require(roots(code,states,620,'rsi')=={3624},'first frame length-array pointer is original workspace')
    for slot,offset in model.ROOTS.items():
        s.require(roots(code,states,642,slot)=={offset},'actual incoming pointer cell matches loop invariant')
    s.require(code[619]=='movl $0, (%r11)' and roots(code,states,619,'r11')=={5248},
        'four-byte readiness reset stays in original four-element array')


def selected_clears(code,edges,states):
    effects=[]
    for site,(load,cmp,branch) in CLEARS.items():
        slot=176+8*list(CLEARS).index(site)
        s.require(code[load]==f'movq {slot}(%rbp), %rax' and
            code[cmp]==('cmpq $4, %rax' if site==1231 else 'cmpq $3, %rax') and
            code[branch]==('jae .B228' if site==1231 else 'ja .B228') and
            code[site]=='movb $0, (%rcx,%rax)', 'exact selected-lane load, unsigned guard and one-byte clear')
        s.require(states[cmp]['rax']==states[site]['rax']=={load} and
            roots(code,states,site,'rcx')=={5248},'same guarded selected index and original ready-array base')
        for at in range(cmp,site+1):
            s.require({p for p,ds in edges.items() if at in ds}=={at-1},'no entry past selected-lane guard')
        s.require(edges[branch]==[code.index('.B228:'),branch+1],'unsigned failure leaves clear path')
        effects.append(dict(site=site,possible_write_spans=[[5248+i,5249+i] for i in range(4)]))
    return effects


def separation(effects,geometry):
    objects=geometry['executor_entry_objects'];start,end=objects['workspace']
    s.require(end-start==5260 and start>=-1200+1128,'original workspace allocation and child-frame separation')
    for lo,hi in effects:
        s.require(0<=lo<hi<=5260,'bounded workspace write extent')
        s.require(all(start+hi<=a or b<=start+lo for key,(a,b) in objects.items() if key!='workspace'),
            'all loop/reset/clear writes exclude other simultaneous caller allocations')


def inspect(bodies,assembly,caller,squeeze,absorb,vector,previous):
    n=o.reconcile.terminal.shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==squeeze['function']==absorb['function']==vector['function']==
        previous['function']==n['executor'] and squeeze['restored_lane_index_input_control_and_frame_pointers_checked'] and
        absorb['cursor_block_count_and_absorbing_to_ready_transition_checked'] and
        vector['completed_group_readiness_cleared_before_rescan'] and
        previous['original_workspace_and_guarded_lane_checked'], 'replayed loop semantics and prior write footprints')
    geometry=o.reconcile.terminal.shape.reject.digest.geometry()
    s.require(caller['geometry']==geometry,'same resident caller geometry')
    edges,_=o.reconcile.graph(code,assembly);spans,_,_=o.frame_writes(code,edges)
    states=w.definitions(code,edges,spans,model.SLOTS)
    loop_entry(code,edges,states);clears=selected_clears(code,edges,states)
    lanes=[model.check_lane(code,edges,spans,lane) for lane in range(4)]
    effects=[[5248,5252]]+[span for row in clears for span in row['possible_write_spans']]+[
        row['span'] for lane in lanes for row in lane['writes']]
    separation(effects,geometry)
    s.require(set(previous['pending_non_frame_store_sites'])==SITES,'all remaining executor store sites assigned')
    return dict(function=n['executor'],readiness_reset=dict(site=619,span=[5248,5252]),
        selected_readiness_clears=clears,per_lane_effects=lanes,store_sites=sorted(SITES),
        single_entry_loop_and_four_lane_induction_checked=True,
        all_normal_predecessor_cursor_and_index_restores_checked=True,
        workspace_and_other_caller_child_frame_separation_checked=True,
        pending_non_frame_store_sites=[],pending_callee_effect_sites=previous['pending_callee_effect_sites'],
        direct_executor_store_inventory_assigned=True,callee_memory_effects_and_win64_nonvolatile_abi_required=True,
        allocation_lifetimes_indirect_aliases_and_private_frame_exception_cleanup_qualified=False)
