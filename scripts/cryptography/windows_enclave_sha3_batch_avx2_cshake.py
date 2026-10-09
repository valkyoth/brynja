"""AVX2 cSHAKE initial-state lifetimes, prefix arithmetic and normal rejection.

Later prefix installation and retained-state transfer are a separate obligation.
"""
import windows_enclave_sha3_batch_avx2_cshake_shapes as shapes
import windows_enclave_sha3_batch_cshake_init as scalar

life,s,L=shapes.life,shapes.s,shapes.L
MASK=(1<<64)-1


def encode(value):
    s.require(type(value) is int and 0<=value<1<<128,'u128 public encoding input')
    width=max(1,(value.bit_length()+7)//8)
    return bytes([width])+value.to_bytes(width,'big')


def counts(rate,name,custom):
    s.require(type(rate) is int and rate in (136,168),'two cSHAKE rates')
    fixed=sum(len(encode(v)) for v in (rate,name,custom))*8
    bits=scalar.add128(name,fixed)
    if bits is not None:bits=scalar.add128(bits,custom)
    if bits is None:return None
    low,high=bits&MASK,bits>>64
    shifted=((high<<61)|(low>>3))&MASK
    low_bytes=shifted+int(bool(low&7));high_bytes=(high>>3)+(low_bytes>>64)
    byte_count=(high_bytes<<64)|(low_bytes&MASK)
    # Both emitted paths call the public u128 remainder runtime.
    rem=byte_count%rate
    rounded=scalar.add128(byte_count,rate-rem if rem else 0)
    s.require(rounded is not None and rounded<=(1<<125)+167,'rounding below u128 overflow')
    return dict(bits=bits,bytes=byte_count,expected=rounded if name or custom else 0,
        remaining=name,custom_bits=custom,phase=0 if name or custom else 2,
        customized=bool(name or custom),prefix=[1,rate] if name or custom else [])


def snapshot_schedule():
    return [('produce',),('copy','frame',2640,'saved',8,8),('accept',),
        ('copy','frame',1696,'saved',0,1),('copy','frame',1697,'frame',705,943),
        ('copy','frame',2648,'frame',1656,32),('copy','frame',2680,'frame',1688,8),
        ('copy','saved',0,'frame',704,1),('copy','saved',8,'frame',1648,8),
        ('encode','rate',2718),('length','rate',2974),
        ('encode','name',304),('length','name',560),
        ('encode','custom',1696),('length','custom',1952),('fields',)]


def snapshot(rate,name,custom,steps=None):
    fields=counts(rate,name,custom)
    s.require(fields is not None,'snapshot field model requires successful arithmetic')
    values={'rate':rate,'name':name,'custom':custom}
    memory={n:[('unknown',n,i) for i in range(size)] for n,size in (('frame',4888),('saved',16))}
    result=[('opaque-result',i) for i in range(992)]
    result[576:584]=[('authority',i) for i in range(8)]
    result[938]=255;result[944:952]=[0]*8
    original=memory['frame'].copy();produced=accepted=complete=False;encoded={};read={}
    def region(n,at,width):
        s.require(n in memory and type(at) is int and type(width) is int and width>0 and
            (32 if n=='frame' else 0)<=at and at+width<=len(memory[n]),'bounded constructor snapshot region')
        return memory[n]
    def copied():
        s.require(accepted and memory['frame'][704:1696]==result,'all992 returned origins saved before result reuse')
    for step in snapshot_schedule() if steps is None else steps:
        s.require(not complete,'no mutation after live prefix initialization')
        if step[0]=='produce':
            s.require(not produced,'one helper result');produced=True;memory['frame'][1696:2688]=result;continue
        if step[0]=='accept':
            s.require(produced and not accepted and memory['saved'][8:16]==[0]*8,'returned success discriminant before payload reads')
            accepted=True;continue
        if step[0]=='copy':
            _,src,at,dst,end,width=step
            s.require(produced and (accepted or step==('copy','frame',2640,'saved',8,8)),
                'only discriminant read before success')
            s.require(src!=dst or at+width<=end or end+width<=at,'nonoverlapping result copies')
            value=region(src,at,width)[at:at+width];region(dst,end,width)[end:end+width]=value;continue
        copied()
        if step[0]=='encode':
            _,kind,at=step;s.require(kind in values and kind not in encoded,'one public length encoding per input')
            data=encode(values[kind]);encoded[kind]=(at,len(data))
            region('frame',at,258)[at:at+258]=list(data)+[0]*(256-len(data))+list(len(data).to_bytes(2,'little'))
        elif step[0]=='length':
            _,kind,at=step
            s.require(kind in encoded and kind not in read and at==encoded[kind][0]+256,'length consumed from exact initialized encoding')
            raw=region('frame',at,2)[at:at+2]
            s.require(raw==list(encoded[kind][1].to_bytes(2,'little')),'live length survives until read')
            read[kind]=encoded[kind][1]
        else:
            s.require(step==('fields',) and set(read)==set(values),'all public lengths consumed before metadata reuses name encoding')
            s.require(read=={k:len(encode(v)) for k,v in values.items()},'exact nontruncated public lengths')
            for at,width,value in ((304,16,name),(320,16,custom),(336,16,0),(352,16,fields['expected']),
                (368,8,rate),(376,2,0),(378,1,fields['phase'])):
                region('frame',at,width)[at:at+width]=value.to_bytes(width,'little')
            complete=True
    copied();s.require(complete,'prefix active fields initialized before first absorption')
    s.require(memory['frame'][704+576:704+584]==result[576:584],'authority unchanged by public encodings and metadata')
    s.require(memory['frame'][32:304]==original[32:304] and memory['frame'][2976:]==original[2976:],
        'modeled writes stay below live state or inside declared encoding buffers')
    s.require(all(type(v) is int for v in memory['frame'][304:379]),'all75 active prefix bytes initialized')
    return dict(result_span=[1696,2688],local_state_span=[704,1696],active_prefix_span=[304,379],
        physical_prefix_span=[304,384],authority_local_span=[1280,1288],
        encoding_spans=[[2718,2976],[304,562],[1696,1954]],
        all_result_origins_saved_before_reuse=True,public_lengths_read_before_metadata_reuse=True,
        padding_initialized_by_prefix_fields=False,retained_transfers_qualified=False,private_frame_erasure_qualified=False)


def prefix_path(rate,name,custom,fail=None):
    s.require(fail in (None,'initial','rate_update','name_update','advance'),'enumerated normal helper failure')
    state=counts(rate,name,custom);calls=['initial']
    if fail=='initial':
        return dict(result=6,local_core=False,prefix_initialized=False,calls=calls,
            caller_memory_wipes=0,caller_scratch_wipes=0,prefix_pending_clear=False,published=False)
    if state is None:
        return dict(result=6,local_core=True,prefix_initialized=False,calls=calls,
            caller_memory_wipes=2,caller_scratch_wipes=1,prefix_pending_clear=False,
            restored_plan_base=1024,local_core_dead=True,published=False)
    if not state['customized']:
        s.require(fail is None,'no prefix helper call exists for empty N/S')
        return dict(result=-1,calls=calls,emitted=0,remaining=0,phase=2,used=0,published=False)
    for helper in ('rate_update','name_update','advance'):
        calls.append(helper)
        if fail==helper:
            return dict(result=6,local_core=True,prefix_initialized=True,calls=calls,
                caller_memory_wipes=3 if helper!='advance' else 2,caller_scratch_wipes=1,
                prefix_pending_clear=True,restored_plan_base=1024,local_core_dead=True,published=False)
    emitted=2+len(encode(name))+(len(encode(custom)) if name==0 else 0)
    return dict(result=-1,calls=calls,emitted=emitted,remaining=name or custom,
        phase=0 if name else 1,used=0,published=False)


def geometry(ir,prior):
    widths={shapes.ENCODE:(258,2),shapes.ABSORB:(864,32),shapes.PREFIX+'4bits':(80,16),
        shapes.PREFIX+'7advance':(80,16),shapes.storage.MEMORY_WIPE:(234,None),shapes.storage.SCRATCH_WIPE:(576,32)}
    s.require(prior['prior_semantics_replayed'] and set(widths)|{life.ZERO}<=set(prior['exact_body_reference_extent_and_abi']),
        'encoding/engine/prefix/wipe semantics require exact replay')
    for helper,(width,align) in widths.items():
        abi=life.reuse.abi(ir,helper)
        s.require('noalias' in abi and 'nounwind' in abi and 'dereferenceable('+str(width)+')' in abi,
            'full exclusive nonunwinding helper extent')
        if align:s.require('align '+str(align)+' ' in abi,'actual helper alignment')
    enc=life.reuse.abi(ir,shapes.ENCODE)
    s.require('initializes((0, 258))' in enc and 'writeonly' in enc and 'i128 noundef %1' in enc,'complete public encoding result')
    for helper in (shapes.PREFIX+'4bits',shapes.PREFIX+'7advance'):
        s.require('ptr noalias nofree noundef nonnull align 32 dereferenceable(864) %1' in life.reuse.abi(ir,helper),
            'prefix second argument borrows full disjoint aligned engine')
    absorb=life.reuse.abi(ir,shapes.ABSORB)
    s.require('readonly captures(address, read_provenance) %1' in absorb and
        'range(i64 0, -9223372036854775808) %2' in absorb,'read-only bounded absorption input')
    # Prefix.pending and Prefix.used are outside the separately borrowed Engine.
    s.require(304%16==0 and 704%32==0 and 304+80<=704 and 704+864==1568 and
        1328+234==1562 and 704+576==1280 and 1696%32==0,'disjoint prefix/engine/scratch and authority fields')
    return dict(prefix=[304,384],engine=[704,1568],engine_memory=[1328,1562],session_scratch=[704,1280],
        pending=376,used=377,phase=378,used_zero_preserved_by_engine_absorb=True,
        per_byte_branch_unreachable_from_valid_zero_used=True,public_umodti3_runtime_pending=True,
        all_unwind_paths_qualified=False)


def inspect(bodies,assembly,ir,prior,construction,direct_review):
    name,covered,total=shapes.check(bodies,assembly)
    s.require(direct_review['function']==name and direct_review['direct_constructor_caller_transfers_qualified'],
        'previous direct constructor helper and failure join replay')
    # The constructor itself must still establish the absent prefix before any
    # arithmetic error can drop the freshly saved local Core.
    shapes.direct.helper_contract(bodies,ir)
    lines=life.code(bodies[shapes.direct.initial.NAME])
    part=L('movl $0, 856(%rdi)|movb $-1, 938(%rdi)|movq %r12, 944(%rdi)')
    s.require(any(lines[i:i+len(part)]==part for i in range(len(lines))),'initial Core prefix is absent before any rejection')
    s.require(construction['function']==name and construction['slot_equality_before_indexed_plan_read'] and
        construction['geometry']['home_offsets_from_entry']==[40,48,56] and
        construction['rejection_clears_output_bytes']==1024 and construction['rejection_quarantines_authority'],
        'admitted public inputs, u128 homes and armed outer rejection cleanup')
    return dict(function=name,reviewed_instruction_positions=covered,combined_start_instruction_positions=total,
        geometry=geometry(ir,prior),rates={str(rate):snapshot(rate,1,1) for rate in (136,168)},
        checked_total_bit_additions=2,ceiling_and_rate_rounding_cannot_overflow=True,
        initialized_local_core_before_arithmetic=True,initialized_failures_destroy_local_core_before_outer_rejection=True,
        prefix_initialized_only_after_arithmetic_success=True,cshake_prefix_calls_and_failure_joins_qualified=True,
        retained_constructor_transfers_qualified=False,all_constructor_paths_qualified=False,
        private_frame_erasure_qualified=False,shared_runtime_completion_package=8)
