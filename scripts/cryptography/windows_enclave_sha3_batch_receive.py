"""Request-copy, dispatch and export composition; nested crypto calls stay open."""
import re
import windows_enclave_sha3_batch_receive_scalar as scalar
import windows_enclave_sha3_batch_receive_avx2 as avx2
import windows_enclave_sha3_batch_decode as decode

life=scalar.life
s=life.s
L=scalar.L
TABLES={'scalar':[[34,25,26,27,28,31,31,31,31],[41,42,43,43,44,45,46,47,48,77]],
        'avx2':[[8,9,10,10,11,12,13,14,15,49]],
        'decode':[[41,31,32,33,34,37,37,37,37]]}


def names(bodies,lane):
    n={k:s.one(bodies,'Owner'+str(len(k))+k+'$') for k in (
        'setup_chunk','finish_setup','cancel','begin','start','seal','update','finish','operation','clear','validate_plan')}
    n.update(receive=s.one(bodies,r'worker7receive$'),equal=s.one(bodies,r'equal_same_length'),
             guard=s.one(bodies,r'Operation.*Drop4drop$'))
    if lane=='avx2':n.update(decode=s.one(bodies,r'Header6decode$'),authority=s.one(bodies,r'15check_authority$'))
    return n


def normalize(body,assembly,expected_tables):
    actual=life.code(body)
    tables=list(dict.fromkeys(re.findall(r'\.LJTI\d+_\d+','\n'.join(actual))))
    s.require(len(tables)==len(expected_tables),'complete receiver/decoder dispatch population')
    for i,(table,targets) in enumerate(zip(tables,expected_tables)):
        definitions=re.findall(r'^'+re.escape(table)+r':\n((?:\s*\.long[^\n]+\n)+)',assembly,re.M)
        s.require(len(definitions)==1,'one complete receiver/decoder table definition')
        number=table.split('_')[0].removeprefix('.LJTI')
        entries=[re.sub(r'\s+','',line) for line in definitions[0].splitlines()]
        s.require(entries==[f'.long.LBB{number}_{n}-{table}' for n in targets],
                  'exact operation and identity dispatch destinations')
        actual=[l.replace(table,'TABLE'+str(i)) for l in actual]
    return actual


def contracts(bodies,lane):
    n=names(bodies,lane)
    shapes={n['equal']:decode.equality()}
    if lane=='scalar':shapes[n['receive']]=scalar.shape(n)
    else:
        shapes[n['receive']]=avx2.shape(n,n['receive'].removesuffix('7receive')+'4LIVE')
        shapes[n['decode']]=decode.shape(n)
        shapes[n['authority']]=L('''movb $6, %al|cmpb $4, 9(%rcx)|jne .B2
            cmpb $1, 8(%rcx)|sete %al|negb %al|orb $6, %al|.B2:|retq''')
    return n,shapes


def check_shapes(bodies,assembly,lane):
    n,shapes=contracts(bodies,lane)
    for name,expected in shapes.items():
        tables=TABLES[lane] if name==n['receive'] else TABLES['decode'] if name==n.get('decode') else []
        s.require(normalize(bodies[name],assembly,tables)==expected,
                  'complete receiver/decoder/equality/authority instruction contract')
    return n,shapes


def arguments(ir,n,lane):
    a=life.LAYOUT[lane]
    owner=f'ptr noalias nofree noundef nonnull align {a["align"]} dereferenceable({a["size"]})'
    op='i64 noundef range(i64 1, 0) %operation'
    args=('('+owner+' %owner, ' if lane=='scalar' else '(')+op+', '+\
         f'ptr noalias nofree noundef nonnull dereferenceable({1312 if lane=="scalar" else 1328}) %buffers)'
    s.require(args in life.reuse.abi(ir,n['receive']),'exclusive receiver allocations and actual operation ABI')
    s.require('(ptr noundef nonnull readonly captures(none) %0, ptr noundef nonnull readonly captures(none) %1)' in
              life.reuse.abi(ir,n['equal']),'noncapturing readonly descriptor comparison')
    pointer='ptr noalias nofree noundef nonnull readonly captures(address, read_provenance)'
    tail={
        'start':'i128 noundef %3, i128 noundef %4)',
        'finish_setup':')',
        'update':f', {pointer} %3, i64 noundef range(i64 0, 1025) %4)',
        'finish':f', {pointer} %3, i64 noundef range(i64 0, 1025) %4, i8 noundef %5)',
        'setup_chunk':f', i1 noundef zeroext %3, {pointer} %4, i64 noundef range(i64 0, 1025) %5, i8 noundef %6)',
    }
    for kind,end in tail.items():
        if kind=='start':end=', '+end
        expected='('+owner+' %0, i64 noundef %1, i64 noundef %2'+end
        abi=life.reuse.abi(ir,n[kind])
        s.require(expected in abi and 'noundef range(i8 -1, 7) i8 @' in abi,
                  'exact nested owner operation arguments and status ABI')
    if lane=='avx2':
        s.require('(ptr dead_on_unwind noalias nofree noundef nonnull writable writeonly align 16 captures(none) dereferenceable(304) %0, '
                  'i64 noundef range(i64 1, 0) %1, ptr noalias nofree noundef nonnull readonly captures(none) dereferenceable(304) %2)' in
                  life.reuse.abi(ir,n['decode']),'disjoint complete header decode source/result ABI')
        s.require('(ptr noundef nonnull readonly align 8 captures(address) %0)' in
                  life.reuse.abi(ir,n['authority']),'actual nonmutating authority check ABI')


def selectors(operation):
    """Model only public u64 selector arithmetic from the exact decoder bodies."""
    s.require(0<=operation<1<<64,'u64 operation')
    mask=(1<<64)-1;delta=(operation-92)&mask
    # x86 masks the shift count; the separate delta<5 check excludes aliases.
    payload=delta<5 and bool((27>>(delta&63))&1)
    planned=(((operation-90)&mask)&(mask^8))==0
    admitted=((operation-100)&mask)>=((1<<64)-10)
    return dict(admitted=admitted,payload=payload,planned=planned)


def inspect(bodies,assembly,ir,lane,retained,storage,transitions,admission):
    s.require(retained['initialization_precedes_live_publication'] and retained['exact_page_identity_before_receive'] and
              retained['resident']['complete_buffer_destructor_checked'],'receiver requires actual placed owner and cleared bounded buffers')
    s.require(storage['state_destructor']['typed_payload_cleanup_composed'] and
              storage['begin']['source_destination_disjoint_by_abi'],'receiver requires state destruction and plan placement')
    s.require(transitions['unfinished_guard_clears_and_quarantines'] and transitions['phase_match_before_admission'] and
              transitions['checked_next_sequence'],'receiver requires guard, phase and sequence semantics')
    s.require(admission['all_instructions_and_dispatch_cases_checked'],'receiver requires complete plan validator')
    n,shapes=check_shapes(bodies,assembly,lane);arguments(ir,n,lane)
    s.require(admission['function']==n['validate_plan'] and storage['begin']['function']==n['begin'] and
              all(transitions['functions'][k]==n[k] for k in ('operation','seal','cancel','clear','guard')),
              'receiver calls the actually reproduced lifecycle and plan helpers')
    # These are simultaneous frame regions, not separate allocations or erased padding.
    regions=({'plan':[240,432],'header_or_begin_or_guard':[432,720],'empty_plan':[720,912]}
             if lane=='scalar' else {'begin_or_guard':[176,368],'decoded_header':[368,672]})
    frame=920 if lane=='scalar' else 680
    ordered=sorted(regions.values())
    s.require(all(32<=lo<hi<=frame for lo,hi in ordered) and
              all(a[1]<=b[0] for a,b in zip(ordered,ordered[1:])), 'bounded disjoint receiver frame regions')
    return dict(functions=n,instructions_and_labels={name:len(v) for name,v in shapes.items()},
        full_decoder_body_checked=True,descriptor_semantic_fields_checked=24,plan_bytes=192,
        copied_header_bytes=288 if lane=='scalar' else 304,payload_limit=1024,
        public_operations=list(range(90,100)),payload_operations=[92,93,95,96],plan_operations=[90,98],
        header_version=11 if lane=='scalar' else 17,avx2_route_identity_checked=lane=='avx2',
        source_end_overflow_rejected=True,actual_host_source_dereference_by_OS_only=True,
        avx2_second_decode_and_length_equality=lane=='avx2',
        payload_pointer_retained_from_worker_buffer=True,receiver_stack_regions=regions,
        export_requires_phase=4,export_checks_all_admitted_plan_fields=True,export_bytes=1024,
        export_success_clears_owner=True,export_failure_guard_then_quarantine=True,
        export_post_copy_authority_recheck=lane=='avx2',export_host_bytes_rollback_claimed=False,
        shared_calls_require_serialized_fixed_C_transport=True,
        nested_crypto_operation_bodies_and_pointer_preservation_qualified=False,
        decoder_copies_and_frame_padding_individually_erased=False,
        all_unwind_paths_qualified=False,whole_image_qualified=False,shared_completion_package=8)
