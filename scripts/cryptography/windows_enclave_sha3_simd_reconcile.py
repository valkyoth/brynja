"""Executor coverage and normal CFG ordering, not pointer/exception qualification.

The parent replays each semantic region before passing its report here. The
finite traversal deliberately overapproximates conditional and table branches.
Wipe argument provenance and physical storage lifetimes remain separate work.
"""
import re
import windows_enclave_sha3_simd_terminal as terminal
life,s=terminal.life,terminal.s

REGIONS=(
    ('reject','entry_region',0,69),('frame','region',69,454),
    ('reject','eligibility_region',454,510),('reject','normal_rejection_region',510,588),
    ('squeeze','setup_region',587,624),('squeeze','ready_dispatch_region',624,648),
    ('absorb','region',648,920),('squeeze','squeeze_region',920,992),
    ('vector','region',992,1253),('scalar','region',1253,1343),
    ('terminal','bridge_region',1343,1425),('terminal','size_admission_region',1425,1482),
    ('output','output_prepare_region',1482,1542),('output','output_copy_and_cleanup_region',1542,1602),
    ('terminal','report_region',1596,1676))
TABLES={123:(0,(44,18,43,45,19,18,19,18)),
    718:(1,(103,103,112,103,107,118,110,108,119)),
    759:(1,(103,103,112,103,107,118,110,108,119))}


def coverage(name,reviews,size):
    s.require(size==1676 and set(reviews)=={row[0] for row in REGIONS},
        'complete executor and exactly eight replayed region reports')
    owners=[[] for _ in range(size)]
    for key,field,lo,hi in REGIONS:
        review=reviews[key]
        actual=review['functions']['executor'] if key=='output' else review['function']
        s.require(actual==name and review[field]==[lo,hi],'same executor and exact reviewed region extent')
        for at in range(lo,hi):owners[at].append(key+'.'+field)
    s.require(all(owners),'no executor coverage holes')
    overlaps={at:labels for at,labels in enumerate(owners) if len(labels)>1}
    s.require(set(overlaps)=={587,*range(1596,1602)} and all(len(v)==2 for v in overlaps.values()),
        'only shared setup label and final wipe overlap')
    return dict(positions=size,region_count=len(REGIONS),
        regions=[dict(review=k,field=f,extent=[lo,hi]) for k,f,lo,hi in REGIONS],
        overlaps={str(k):v for k,v in overlaps.items()},uncovered_positions=[])


def graph(code,assembly):
    labels={line[:-1]:at for at,line in enumerate(code) if line.endswith(':')}
    s.require(len(labels)==sum(line.endswith(':') for line in code),'unique executor CFG labels')
    s.require({at for at,l in enumerate(code) if l.startswith('jmpq *')}==set(TABLES),
        'all three assigned indirect executor branches')
    tables={}
    for at,(number,targets) in TABLES.items():
        name=f'.LJTI30_{number}'
        found=re.findall(r'(?m)^'+re.escape(name)+r':\s*\n((?:\s*\.long[^\n]*\n)+)',assembly)
        s.require(len(found)==1 and re.findall(r'\.long\s+(\S+)',found[0])==
            [f'.LBB30_{v}-{name}' for v in targets],'actual complete local dispatch table')
        s.require(code[at]=='jmpq *%rax','reviewed computed branch register')
        tables[at]=['.B'+str(v) for v in targets]
    edges={}
    for at,line in enumerate(code):
        if line in ('retq','ud2'):edges[at]=[];continue
        if line.startswith('j'):
            op,target=line.split(maxsplit=1)
            s.require(op in ('jmp','jmpq','je','jne','ja','jae','jb','jbe','jg','jge','jl','jle','js','jns','jo','jno'),
                'closed normal branch opcode population')
            targets=tables.get(at) if target.startswith('*') else [target]
            s.require(targets and all(v in labels for v in targets),'assigned local CFG destinations')
            edges[at]=[labels[v] for v in targets]
            if op not in ('jmp','jmpq'):edges[at].append(at+1)
        else:edges[at]=[at+1]
        s.require(all(v<len(code) for v in edges[at]),'no normal CFG fallthrough escape')
    return edges,tables


def ordering(code,edges,workspace,staging,work):
    """Both buffers start live; work regions conservatively make both live again.

    This is intentionally not an opcode-based secret-write classifier. Replayed
    region semantics cover the public report/epilogue outside these intervals.
    """
    s.require(workspace and staging and work and not (workspace&staging or (workspace|staging)&work),
        'nonvacuous disjoint ordering effects')
    pending=[(0,True,True)];seen=set();returns=set();traps=set();wipes=set();touched=set()
    while pending:
        at,wlive,slive=pending.pop()
        if (at,wlive,slive) in seen:continue
        seen.add((at,wlive,slive))
        s.require(at in edges,'bounded cleanup CFG state')
        if at in work:wlive=slive=True;touched.add(at)
        if at in workspace:wlive=False;wipes.add(at)
        if at in staging:
            s.require(not wlive,'full workspace wipe precedes staging wipe')
            slive=False;wipes.add(at)
        if code[at]=='retq':
            s.require(not wlive and not slive,'both full wipes before every normal return')
            returns.add(at)
        elif code[at]=='ud2':traps.add(at)
        else:
            s.require(edges[at],'nonterminal cleanup path has a successor')
            pending.extend((n,wlive,slive) for n in edges[at])
    s.require(returns and touched and wipes==workspace|staging,'reachable returns, work and every assigned wipe')
    return dict(normal_returns=sorted(returns),terminal_traps=sorted(traps),
        reachable_states=len(seen),reached_work_positions=len(touched),wipe_sites=sorted(wipes))


def inspect(bodies,assembly,reviews):
    n=terminal.shape.names(bodies);code=life.code(bodies[n['executor']])
    regions=coverage(n['executor'],reviews,len(code))
    s.require(reviews['reject']['normal_rejection_clears_workspace_staging_then_destinations'] and
        reviews['terminal']['successful_report_after_workspace_and_staging_wipe'] and
        reviews['output']['all_four_source_extents_preflight_before_first_copy'],
        'replayed normal cleanup and output prerequisites')
    edges,tables=graph(code,assembly)
    workspace={73,530,1588,1598};staging={533,1591,1601}
    zero=life.ZERO
    s.require({i for i,l in enumerate(code) if l=='callq '+n['workspace_wipe']}==workspace,
        'all complete workspace wipe sites')
    for at in staging:
        s.require(code[at]=='callq '+zero and code[at-2]=='movl $1024, %edx',
            'assigned full staging wipe and length')
    work=set(range(74,510))|set(range(587,1586))
    result=ordering(code,edges,workspace,staging,work)
    s.require(result['normal_returns']==[586] and result['terminal_traps']==[1467],
        'complete normal return and non-success panic terminal population')
    return dict(function=n['executor'],coverage=regions,normal_ordering=result,
        dispatch_sites={str(k):v for k,v in tables.items()},
        all_executor_positions_have_replayed_region_review=True,
        normal_cfg_workspace_then_staging_wipe_order_checked=True,
        conditional_edges_overapproximated=True,buffers_live_on_entry=True,
        wipe_argument_provenance_still_required=True,
        complete_machine_pointer_lifetimes_and_nonoverlap_qualified=False,
        private_frame_and_exception_cleanup_qualified=False,
        terminal_paths_are_not_cleanup_success=True)
