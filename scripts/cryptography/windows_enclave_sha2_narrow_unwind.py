"""Join saved narrow pointer lifetimes to bound FH3 cleanup callsite states.

Only emitted caller-side slot availability is established. OS dispatch, private
callee frames, indirect writes and enclosing-window cleanup remain separate.
"""
from collections import Counter
import re
import windows_enclave_sha2_narrow_cfg as n
import windows_enclave_sha2_simd_authority as authority
from windows_enclave_sha2_descriptor_ir import function
o,s=n.o,n.s


def inspect(bodies,assembly,ir,lines,states,pointers):
    name=s.one(bodies,r'Resident6digest$')
    tables=authority.cleanup_tables(assembly,bodies,'simd256')
    handlers=authority.digest_handlers(bodies,'simd256')
    chains=tables['parents'][name]['ordered_handlers_from_ip']
    needed={};all_reads={}
    for handler,review in handlers.items():
        if review['parent']!=name:continue
        body=s.lines(bodies[handler]);slots={}
        for slot in (88,112,152):
            uses=n.reads(body,slot)
            if uses:slots[slot]=uses
        s.require(112 not in slots,'cleanup does not consume repurposed per-lane input slot')
        needed[handler]=set(slots);all_reads[handler]={str(k):v for k,v in slots.items()}
    annotations=[v for v in lines if v.startswith('.Ltmp')]
    s.require(annotations==[f'.Ltmp{i}:' for i in range(46,68)],'complete eleven protected call regions')
    calls=[]
    for number in range(46,68,2):
        first=lines.index(f'.Ltmp{number}:');last=lines.index(f'.Ltmp{number+1}:')
        sites=[i for i in range(first,last) if lines[i].startswith('callq ')]
        s.require(len(sites)==1,'exactly one call per protected region');calls+=sites
    # LLVM invokes are precisely the potentially unwinding calls. Do not demand
    # initialized slots at unrelated nounwind cleanup calls in shared blocks.
    invokes=[v for v in function(ir,name) if 'invoke ' in v]
    targets=[]
    for line in invokes:
        match=re.search(r'invoke .*?([@%][\w.$-]+)\(',line)
        s.require(match is not None,'assigned invoke target syntax')
        targets.append(match[1][1:] if match[1].startswith('@') else 'indirect')
    actual=[lines[at][6:] if not lines[at][6:].startswith('*') else 'indirect' for at in calls]
    s.require(len(calls)==11 and Counter(targets)==Counter(actual),'all LLVM invokes have emitted call regions')
    active=[];rows=[]
    for at,line in enumerate(lines):
        if line.endswith(':') and line[:-1] in chains:active=chains[line[:-1]]
        if at not in calls:continue
        s.require(at in states and active,'every potentially unwinding call has an active cleanup chain')
        required=set().union(*(needed[handler] for handler in active))
        for slot in required:
            expected=pointers['authority_initializer' if slot==88 else 'owner_initializer']
            s.require(states[at][slot]=={expected},
                      'each active unwind handler sees its original saved pointer at every call')
        rows.append(dict(call=at,handlers=active,required_pointer_slots=sorted(required)))
    s.require(rows and any(88 in row['required_pointer_slots'] for row in rows)
              and any(152 in row['required_pointer_slots'] for row in rows),
              'nonvacuous authority and owner unwind-pointer composition')
    return dict(handler_slot_reads=all_reads,callsite_lifetimes=rows,
        original_saved_pointers_available_at_all_invoke_calls=True,
        scalar_input_slot_never_read_by_cleanup=True,
        os_dispatch_and_indirect_memory_preservation_required=True)
