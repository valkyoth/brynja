"""Inner lane setup/squeeze and copy/mask bounds; absorption remains separate."""
import hashlib
import re
import windows_enclave_sha3_simd_squeeze_shape as shape
import windows_enclave_sha3_simd_squeeze_model as model
life,s,L=shape.life,shape.s,shape.L


def names(bodies):
    return shape.digest.helpers.names(bodies)|{role:s.one(bodies,pattern) for role,pattern in (
        ('mask',r'secret_memory22apply_secret_byte_mask$'),('mask_leaf',r'secret_memory_mask9mask_byte$'))}


def mask_helper(bodies,ir,n):
    leaf=bodies[n['mask_leaf']];markers=('BRYNJA_MASK_BEGIN','BRYNJA_MASK_ERASE','BRYNJA_MASK_END')
    s.require(leaf.count('#APP')==leaf.count('#NO_APP')==1 and
        all(leaf.count(m)==1 for m in markers),'one opaque mask region and marker population')
    opaque=leaf.split('#APP')[1].split('#NO_APP')[0]
    s.require(all(m in opaque for m in markers),'mask markers inside opaque boundary')
    positions=[opaque.index(m) for m in markers]
    s.require(positions==sorted(positions),'mask/erase/end marker order')
    operation=L('movzbl (%rcx), %eax|andb %dl, %al|orb %r8b, %al|movb %al, (%rcx)')
    s.require(s.lines(opaque.split(markers[0])[1].split(markers[1])[0])==operation and
        s.lines(opaque.split(markers[1])[1].split(markers[2])[0])==['xorl %eax, %eax'],
        'specialized mask operation and working-register erasure')
    s.require(life.code(leaf)==['xorl %r8d, %r8d']+operation+L('xorl %eax, %eax|retq') and
        life.code(bodies[n['mask']])==['jmp '+n['mask_leaf']],
        'complete zero-add mask leaf and tail wrapper')
    for role,args in (
        ('mask','ptr noalias nofree noundef nonnull dereferenceable(1) %0, i8 noundef range(i8 1, -128) %1'),
        ('mask_leaf','ptr noundef nonnull %0, i8 noundef zeroext range(i8 1, -128) %1')):
        s.require(life.reuse.abi(ir,n[role])==f'define internal fastcc void @{n[role]}({args}) unnamed_addr '+
            '{ noinline nounwind uwtable '+shape.digest.target()+' } {','exact mask helper ABI')
    return dict(functions={k:n[k] for k in ('mask','mask_leaf')},keep_mask_range=[1,128],
        added_bits=0,working_register_erased='eax',opaque_stack_accesses=0)


def inspect(bodies,asm,ir,constants,caller,framing,rejection):
    n=names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==n['executor'] and
        caller['helpers']['copy_wrapper_checks_equal_lengths'] and
        caller['helpers']['geometry']==shape.digest.helpers.geometry() and
        framing['public_framing_fields_and_output_offsets_checked'] and
        rejection['normal_rejection_clears_workspace_staging_then_destinations'],
        'replayed squeeze caller/copy/framing/rejection prerequisites')
    s.require(len(code)==1676 and code[587:624]==shape.setup() and
        code[624:648]==shape.ready() and code[920:992]==shape.squeeze(n),
        'complete saved lane setup/dispatch/ready/squeeze regions')
    label='switch.table.'+n['executor'];raw=b''.join(x.to_bytes(8,'little') for x in model.RATES)
    s.require(label in constants and constants[label]['bytes']==64 and
        constants[label]['sha256']==hashlib.sha256(raw).hexdigest(),'actual linked eight-identity rate table')
    rows=re.findall(r'^'+re.escape(label)+r':\n((?:\s*\.quad[^\n]+\n)+)',asm,re.M)
    s.require(len(rows)==1 and list(map(int,re.findall(r'\.quad\s+(\d+)',rows[0])))==list(model.RATES),
        'saved assembly rate table agrees with linked bytes')
    helpers=mask_helper(bodies,ir,n)
    actual=code[920:992]+code[624:648]
    for tag in range(8):
        for written in (0,model.RATES[tag],256):model.check(actual,n,tag,2047,written,768,tag%4)
    return dict(function=n['executor'],setup_region=[587,624],ready_dispatch_region=[624,648],
        squeeze_region=[920,992],instruction_positions=133,mask=helpers,
        linked_rates=list(model.RATES),state_stride=200,state_capacity=200,staging_capacity=1024,
        copy_lengths_equal_and_at_most_rate=True,final_partial_byte_uses_low_bit_mask=True,
        written_counter_committed_after_successful_copy=True,
        restored_lane_index_input_control_and_frame_pointers_checked=True,
        saved_region_oracle_cases=24,
        all_incoming_pointer_lifetimes_and_storage_nonoverlap_qualified=False,
        absorption_permutation_work_accounting_and_report_qualified=False,
        exception_and_private_frame_erasure_qualified=False)
