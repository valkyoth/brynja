"""Actual nineteen-route unwind/prologue reconciliation, not a whole-stack proof.

Preserve exception handlers as explicit boundaries. Metadata is checked against
the instructions which allocate each fixed frame; no absent metadata is silently
assigned a zero frame. Body CFG, call-site alignment and indirect targets remain
distinct obligations, not consequences of an unwind record.
"""
import windows_enclave_runtime_arithmetic as arithmetic
import windows_enclave_caller_unwind as unwind

workers=arithmetic.workers
r=workers.catalog
require,digest=r.require,r.digest
NONVOL=(3,5,6,7,12,13,14,15)


def decode(rows,item):
    start,end,address=item
    header=unwind.read(rows,address,4);version,flags=header[0]&7,header[0]>>3
    prolog,count,frame=header[1:]
    require(version==1 and flags in (0,1,2,3) and 0<=prolog<=end-start,
        'explicit nonchained version-one worker metadata')
    require(frame==0 or frame&15 in NONVOL,'nonvolatile frame base')
    slots=unwind.read(rows,address+4,count*2)
    operations=[];index=0;previous=256;stack=0
    while index<count:
        offset,value=slots[index*2:index*2+2];op,info=value&15,value>>4
        require(0<offset<=previous and offset<=prolog,'ordered actual prologue endpoints')
        previous=offset
        widths={0:0,1:1 if info==0 else 2,2:0,3:0,4:1,5:2,8:1,9:2}
        require(op in widths and (op!=1 or info<=1),'known unwind allocation/save')
        extra=widths[op];require(index+extra<count,'complete operation operand')
        operand=int.from_bytes(slots[(index+1)*2:(index+extra+1)*2],'little')
        amount=0
        if op==0:
            require(info in NONVOL,'nonvolatile pushed register');amount=8
        elif op==1:
            amount=operand*(8 if info==0 else 1)
            require(amount>0 and amount%8==0,'positive aligned allocation')
        elif op==2:amount=info*8+8
        elif op==3:require(info==0 and frame&15,'declared frame-register setup')
        elif op in (4,5):require(info in NONVOL,'saved nonvolatile GPR')
        else:require(6<=info<=15,'saved nonvolatile XMM register')
        stack+=amount
        operations.append(dict(end=offset,opcode=op,register=info,operand=operand,bytes=amount))
        index+=extra+1
    require(stack<65536,'bounded fixed worker frame')
    handler=None
    if flags:
        handler=int.from_bytes(unwind.read(rows,address+4+((count+1)&~1)*2,4),'little')
        require(any(row['flags']&0xe0000000==0x60000000 and
            row['rva']<=handler<row['rva']+min(len(row['code']),row['virtual_size'])
            for row in rows),'explicit executable exception handler boundary')
    return dict(prologue_bytes=prolog,fixed_bytes=stack,frame_register=frame,
        handler_flags=flags,handler_rva=handler,operations=operations)


def allocations(code,refs,record):
    """Every unwind allocation has the matching actual COFF instruction."""
    used=[]
    for op in record['operations']:
        kind,end,amount=op['opcode'],op['end'],op['bytes']
        if kind==0:
            register=op['register']
            expected=(b'\x41' if register>=8 else b'')+bytes([0x50+(register%8)])
        elif kind in (1,2):
            small=b'\x48\x83\xec'+bytes([amount]) if amount<=127 else b''
            large=b'\x48\x81\xec'+amount.to_bytes(4,'little')
            if small and code[max(0,end-len(small)):end]==small:expected=small
            elif code[max(0,end-len(large)):end]==large:expected=large
            else:
                expected=b'\xb8'+amount.to_bytes(4,'little')+b'\xe8'+bytes(4)+b'\x48\x29\xc4'
                start=end-len(expected)
                require(any(v['offset']==start+6 and v['symbol']=='__chkstk' and
                    v['trailing']==v['addend']==0 for v in refs),'same constant probed allocation')
        else:continue
        start=end-len(expected)
        require(start>=0 and code[start:end]==expected,'metadata matches complete allocating instruction')
        require(all(end<=a or b<=start for a,b in used),'disjoint allocating instruction spans')
        used.append((start,end))
    require(sum(op['bytes'] for op in record['operations'])==record['fixed_bytes'],
        'all fixed allocation contributions reconciled')
    return sorted(used)


def inspect(image,functions,records):
    rows,table=r.sdk.pe.linked(image);result={}
    for name,(code,refs,runtime) in functions.items():
        bound=records[name];start=bound['rva'];end=start+bound['size']
        matches=[item for item in table if item[0]<end and start<item[1]]
        if not runtime:
            require(not matches,'COFF leaf also absent from PE runtime-function table')
            result[name]=dict(rva=start,bytes=len(code),metadata_present=False,
                fixed_bytes=None,leaf_instruction_review_required=True)
            continue
        require(len(matches)==1 and matches[0][:2]==(start,end),'exact actual worker function extent')
        record=decode(rows,matches[0])
        spans=allocations(code,refs,record)
        result[name]=dict(rva=start,bytes=len(code),metadata_present=True,**record,
            allocation_instruction_spans=spans,
            exception_funclet=name.startswith('?'),
            dynamic_alignment_and_body_stack_operations_not_inferred=True)
    return dict(functions=result,worker_count=len(result),
        metadata_count=sum(v['metadata_present'] for v in result.values()),
        leaf_count=sum(not v['metadata_present'] for v in result.values()),
        exception_handler_count=sum(bool(v.get('handler_flags')) for v in result.values()),
        maximum_fixed_frame_bytes=max(v['fixed_bytes'] or 0 for v in result.values()),
        cumulative_depth_proven=False,nonvolatile_restore_proven=False)
