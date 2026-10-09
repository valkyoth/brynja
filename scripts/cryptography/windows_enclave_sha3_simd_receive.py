"""Complete receiver boundary contract; nested descriptor/digest bodies stay open."""
from hashlib import sha256
import windows_enclave_sha3_simd_receive_shape as shape

worker,life,s,L=shape.worker,shape.life,shape.s,shape.L
MASK=(1<<64)-1


def names(bodies):
    return worker.names(bodies)|worker.owner.names(bodies)|{
        role:s.one(bodies,pattern) for role,pattern in (
            ('array',r'^_RINv.*try_from_fn.*keccak_simd4Lane.*keccak_simd_worker7receive'),
            ('bits',r'^[^?].*Fips202BitString3new$'),
            ('digest',r'^[^?].*keccak_simd_resident.*Resident6digest$'))}


def metadata(operation,words):
    """Translate the checked public u64 branch predicates; never touch payload."""
    s.require(0<=operation<=MASK and len(words)==48 and all(0<=x<=MASK for x in words),'wire u64 population')
    if words[0]!=22 or words[1]==0 or words[3]!=2:return False
    if ((operation-101)&MASK)<2:
        if words[2]!=0:return False
    elif operation!=100:return False
    for lane in range(4):
        fields=words[4+11*lane:15+11*lane]
        if operation==102:
            if any(fields):return False
            continue
        tag=(fields[0]-1)&MASK
        if tag>7 or fields[1]>2048:return False
        if tag<=3 and fields[1]!=(224,256,384,512)[tag]:return False
        for part in range(3):
            length,last,source=fields[2+3*part:5+3*part]
            if operation==101 or length==0:
                if length|last|source:return False
                continue
            if length>1024 or source==0:return False
            if part==0:
                if source+length>MASK or ((last-9)&MASK)<MASK-7:return False
            else:
                if tag&6!=6 or ((last-1)&MASK)>7 or length>(source^MASK):return False
    return True


def decoded_transfer():
    # Byte provenance only. Padding is copied as unknown padding, not asserted
    # initialized/cleared. The raw wire header is dead before this destination
    # is reused. The schedule comes from the complete checked .B43 block.
    memory=[('unknown',i) for i in range(1512)]
    source=[('decoded',i) for i in range(288)];memory[80:368]=source
    first=memory[80];tag=memory[88]
    memory[48:52]=memory[81:85];memory[51:55]=memory[84:88]
    memory[784:1063]=memory[89:368]
    memory[368]=first;memory[369:373]=memory[48:52];memory[372:376]=memory[51:55]
    memory[376]=tag;memory[377:656]=memory[784:1063]
    s.require(memory[368:656]==source,'exact decoded metadata transfer including uninterpreted padding')
    return dict(source=[80,368],snapshot=[784,1063],destination=[368,656],bytes=288,
                padding_initialization_or_erasure_claimed=False)


def geometry():
    slots=[]
    for index in range(12):
        lane,part=divmod(index,3);copy_index=22+index;descriptor_index=274+3*lane
        length=272+8*copy_index;source=368+8*copy_index
        bit_length=-1744+8*descriptor_index+8*part
        last=366+descriptor_index+part
        payload=3072*lane+1024*part;destination=1064+112*lane+32*part
        s.require(length==bit_length==448+8*index and source==544+8*index and last==640+index,
                  'decoded fields reach the same copied payload/bitstring lane')
        s.require(payload==index*1024 and destination+32<=1064+112*lane+96,
                  'three descriptors stay in each exact lane')
        slots.append(dict(lane=lane,part=part,copy_kind=copy_index-21,payload=[payload,payload+1024],
            length_frame=length,opaque_source_frame=source,last_frame=last,descriptor=[destination,destination+32]))
    for active in (((368,432),(752,784),(1064,1512)),
                   ((80,112),(112,176),(368,656),(784,816),(1064,1512)),
                   ((80,112),(368,656),(1064,1512))):
        ordered=sorted(active)
        s.require(all(32<=lo<hi<=1512 for lo,hi in ordered) and
            all(a[1]<=b[0] for a,b in zip(ordered,ordered[1:])),'disjoint active descriptor call regions')
    return dict(slots=slots,decoded_plan=[368,432],sequence=432,budget=440,
        bitstring_result=[784,816],lane_array=[1064,1512],result=[80,112],
        active_call_regions_disjoint=True,callee_preservation_and_nonretention_not_yet_qualified=True)


def abis(ir,n):
    target='"target-cpu"="x86-64" "target-features"="'+worker.resident.session.zero.SIMD_FEATURES+'"'
    out='ptr dead_on_unwind noalias nofree noundef nonnull writable writeonly align 8 captures(none)'
    read='ptr noalias nofree noundef nonnull readonly align 8 captures(none)'
    records={
        'receive':('noundef zeroext i1',
            'i64 noundef range(i64 1, 0) %operation, ptr noalias nofree noundef nonnull dereferenceable(12672) %buffers',
            'nounwind uwtable',True),
        'array':('void',out+' dereferenceable(448) initializes((0, 441)) %_0, '+read+
            ' dereferenceable(64) %cb.0, '+read+' dereferenceable(32) %cb.1',
            'inlinehint mustprogress nofree norecurse nosync nounwind willreturn memory(argmem: readwrite, inaccessiblemem: readwrite) uwtable',True),
        'bits':('void',out+' dereferenceable(32) initializes((0, 9)) %0, '+
            'ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) %1, '+
            'i64 noundef range(i64 0, 1025) %2, i8 noundef %3','nounwind uwtable',False),
        'digest':('void',out+' dereferenceable(32) %0, ptr nonnull %.16.val, i64 noundef %1, '+
            'ptr dead_on_return noalias nofree noundef nonnull readonly align 8 captures(none) dereferenceable(448) %2, '+
            'i64 noundef %3','uwtable',True)}
    for role,(result,args,attrs,unwind) in records.items():
        expected=f'define internal fastcc {result} @{n[role]}({args}) unnamed_addr {{ {attrs} {target} }} '+(
            'personality ptr @__CxxFrameHandler3 {' if unwind else '{')
        s.require(life.reuse.abi(ir,n[role])==expected,'receiver/helper complete resolved ABI '+role)


def inspect(bodies,ir,constants,retained,checked_owner):
    n=names(bodies)
    for role in ('receive','live','identity'):
        s.require(retained['functions'][role]==n[role],'receiver actual retained worker '+role)
    for key in ('live_identity_checked_before_receive','return_after_buffer_drop_on_all_normal_request_paths',
                'bounds_readback_and_observe_failure_quarantine_then_drop'):
        s.require(retained[key],'receiver worker prerequisite '+key)
    s.require(retained['buffers_bytes']==12672,'entire receiver buffer allocation')
    for role in ('operation','cancel','check'):
        s.require(checked_owner['functions'][role]==n[role],'actual reviewed owner callee '+role)
    s.require(checked_owner['rejected_operation_clears_output_and_quarantines'] and
        checked_owner['cancellation_clears_output_then_sets_empty'],'receiver reviewed owner cleanup')
    for label,raw in ((shape.ZERO88,bytes(88)),('switch.table.'+n['receive'],
            b''.join(x.to_bytes(8,'little') for x in (224,256,384,512)))):
        s.require(label in constants and constants[label]['bytes']==len(raw) and
            constants[label]['sha256']==sha256(raw).hexdigest(),'actual linked wire validation constant')
    expected=shape.shape(n)
    s.require(life.code(bodies[n['receive']])==expected,'complete SIMD receiver instruction contract')
    abis(ir,n)
    success=s.normal_returns(bodies[n['receive']],'.B82',L(f'''movl $1024, %edx|
        movq %rsi, %rcx|callq {life.ZERO}|movb $-1, 8(%rdi)|movb $0, 1104(%rdi)'''))
    return dict(functions=n,instruction_positions=len(expected),frame_bytes=1512,
        header_bytes=384,wire_version=22,route_identity=2,operations=[100,101,102],
        complete_metadata_before_payload_copy=True,payload_copy_only_for_digest=True,
        source_end_overflow_rejected=True,host_source_dereferenced_only_by_fixed_C_copy=True,
        decoded_transfer=decoded_transfer(),descriptor_geometry=geometry(),
        all_twelve_inputs_bounded_to_separate_1024_byte_worker_slots=True,
        actual_bitstring_inputs_use_local_buffers_not_host_addresses=True,
        all_four_export_plan_identities_and_lengths_compared=True,
        export_bytes=1024,export_requires_ready_phase_and_next_sequence=True,
        export_rechecks_authority_after_copy=True,successful_export_clears_output_and_plan=True,
        export_success_normal_return_sites=success,export_failure_return_is_false=True,
        outer_worker_quarantines_receiver_failure=True,export_host_rollback_claimed=False,
        array_constructor_bitstring_and_digest_bodies_qualified=False,
        nested_pointer_preservation_and_nonretention_qualified=False,
        decoder_padding_or_private_frame_erasure_qualified=False,
        fatal_abort_cleanup_claimed=False,shared_completion_package=8)
