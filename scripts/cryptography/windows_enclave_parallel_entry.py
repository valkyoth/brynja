"""Actual sequential Rust worker entry; outer C/OS lifetime remains conditional."""
import windows_enclave_parallel_lifecycle as life
import windows_enclave_parallel_entry_bytes as byte_contracts
import windows_enclave_wrapper_binding as pe

require,c,s=life.require,life.c,life.s
TABLES=byte_contracts.CONTRACTS


def names(functions,lane):
    result=dict(entry='RetainedWork',buffers_drop=s.one(functions,r'drop_glue.*BuffersE'))
    if lane=='avx2':result['buffers_clear']=s.one(functions,r'Buffers5clear$')
    require(set(result.values())<=set(functions),'all selected entry bodies present')
    return result


def reference_contract(functions,lane):
    n=names(functions,lane);ln=life.names(functions,lane)
    prefix='_RNv'+('CsJ7dH9IFLu0_22parallel_stream_worker' if lane=='scalar'
        else 'Cs6vN7PGL8mdd_27parallel_accelerated_worker')
    live=prefix+'4LIVE'+('.0' if lane=='scalar' else '')
    identity=prefix+'9LIVE_PAGE.0'
    if lane=='scalar':
        state=s.one(functions,r'drop_glue.*parallel_stream_state5StateE')
        drop=s.one(functions,r'Input.*Drop4drop$')
        calls={0x8a:ln['quarantine'],0x92:state,0xa1:drop,0xa9:state,0x134:'memset',
            0x17b:'memset',0x1cc:prefix+'7receive',0x1da:ln['quarantine'],
            0x1e7:s.ZERO,0x1f6:s.ZERO,0x23d:ln['quarantine'],0x247:n['buffers_drop'],
            0x2b3:'PublicParallelObserve',0x2df:n['buffers_drop']}
        data={0x55:(live,0),0xb3:(live,-4),0x13b:(live,0)}
    else:
        calls={0xab:ln['drop'],0xf3:ln['clear'],0x139:ln['clear'],0x175:ln['clear'],
            0x199:'memset',0x1a9:ln['new'],0x1e3:ln['drop'],0x23a:'memset',
            0x28d:prefix+'7receive',0x2ba:ln['clear'],0x2cb:n['buffers_clear'],
            0x31d:ln['clear'],0x32e:n['buffers_drop'],0x386:'PublicParallelObserve'}
        data={at:(live,add) for at,add in ((0x68,0),(0x98,16),(0x9f,-4),(0xc9,-1),
            (0xd3,16),(0x119,16),(0x155,16),(0x1d2,0),(0x1de,16),(0x1ef,16),
            (0x1fd,0),(0x29a,16),(0x2fd,16))}
        data.update({0x81:(identity,0),0xb2:(identity,-4),0x204:(identity,0)})
    result={'entry':sorted([dict(offset=at,symbol=symbol,addend=0,trailing=0)
        for at,symbol in calls.items()]+[dict(offset=at,symbol=symbol,addend=add,trailing=0)
        for at,(symbol,add) in data.items()],key=lambda r:r['offset'])}
    for role in n:
        if role!='entry':result[role]=[dict(offset=at,symbol=s.ZERO,addend=0,trailing=0) for at in (0x15,0x27)]
    return result


def refs_check(bodies,refs,expected):
    require(refs==expected,'exact entry call/global relocation population and operand addends')
    require(set(bodies)==set(expected),'entry body/reference population')
    for role,rows in expected.items():
        for row in rows:
            at=row['offset']
            require(int.from_bytes(bodies[role][at:at+4],'little',signed=True)==row['addend'],
                'actual reference displacement matches reviewed operand')
            if '4LIVE' in row['symbol'] or '9LIVE_PAGE' in row['symbol']:continue
            opcode=0xe9 if role!='entry' and at==0x27 else 0xe8
            require(bodies[role][at-1]==opcode,'reviewed direct call or exact clearing tail call')


def instructions(bodies,lane):
    require(set(bodies)==set(TABLES[lane]),'complete selected worker population')
    for role,contract in TABLES[lane].items():
        code=bodies[role];cursor=0;anchors=[]
        require(len(code)==contract['size'],'exact worker extent')
        for label,at,text in contract['regions']:
            require(label and at==cursor,'complete named worker spans')
            cursor+=len(bytes.fromhex(text));anchors.append((at,text))
        require(cursor==len(code),'no omitted worker bytes')
        life.framing.leaf.finish.windows(code,anchors,contract['branches'])
    return sum(len(code) for code in bodies.values())


def global_storage(image,record,lane):
    rows,_=pe.linked(image)
    targets={n:at for n,at in record['reference_targets'].items() if '4LIVE' in n or '9LIVE_PAGE' in n}
    require(len(targets)==(1 if lane=='scalar' else 2),'all live allocation identity objects')
    spans=[]
    for symbol,at in targets.items():
        size=24 if lane=='avx2' and '4LIVE' in symbol else 8
        matches=[r for r in rows if r['rva']<at+size and at<r['rva']+r['virtual_size']]
        require(at%8==0 and len(matches)==1,'aligned unambiguous identity storage')
        row=matches[0]
        require(row['rva']<=at and at+size<=row['rva']+row['virtual_size'] and
            row['flags']&0xe0000000==0xc0000000,'complete readable writable nonexecutable identity storage')
        spans.append((at,at+size))
    require(all(a[1]<=b[0] or b[1]<=a[0] for i,a in enumerate(spans) for b in spans[i+1:]),
        'live handle and page identity never alias')
    return dict(identity_rvas=targets,regions=[list(r) for r in sorted(spans)],
        serialized_entry_is_external_precondition=True)


def inspect_loaded(inputs,functions,records,lane,pin,mutate=False):
    import windows_enclave_parallel_entry_models as models
    n=names(functions,lane);bodies={r:functions[name][0] for r,name in n.items()}
    refs={r:functions[name][1] for r,name in n.items()}
    refs_check(bodies,refs,reference_contract(functions,lane));count=instructions(bodies,lane)
    identity=global_storage(inputs['image'],records['RetainedWork'],lane)
    geometry=models.buffers(bodies['entry'],lane)
    offsets=models.observed_offsets(lane)
    if lane=='scalar':models.scalar_page_erase(bodies['entry'])
    mutations=0
    if mutate:
        for role,name in n.items():
            code,relocations,kind=functions[name]
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try:c.body_check((bad,relocations,kind),pin['functions'][name])
                except ValueError:mutations+=1
                else:raise AssertionError('accepted worker body mutation')
    return dict(entries={r:records[name] for r,name in n.items()},identity_storage=identity,
        relative_buffer_regions=geometry,reviewed_instruction_bytes=count,
        volatile_buffer_bytes_observed=len(offsets),
        body_byte_mutations_rejected=mutations,
        scalar_page_window_nonoverlap_checked_in_rust=False,
        avx2_page_window_nonoverlap_checked_in_rust=lane=='avx2',
        invalid_entry_quarantines_existing_owner=lane=='avx2',
        normal_close_destroys_typed_state_before_full_page_clear=True,
        actual_receive_export_body_reviewed_here=False,
        whole_private_window_erasure_proved=False,
        requires=['C serialization and no reentry','original page/window admission and lifetime',
            'complete accelerated CPU bundle before Rust entry','normal-return callee contracts',
            'shared runtime stack/copy/transport behavior; package 8'])
