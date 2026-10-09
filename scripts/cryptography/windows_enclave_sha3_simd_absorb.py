"""Saved one-rate absorption/cursor/source review; permutation remains separate."""
import hashlib
import re
import windows_enclave_sha3_simd_absorb_shape as shape
import windows_enclave_sha3_simd_absorb_model as model
import windows_enclave_sha3_simd_absorb_helpers as helpers
life,s=shape.life,shape.s


def inspect(bodies,asm,ir,constants,framing,squeezing):
    n=shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(framing['public_framing_fields_and_output_offsets_checked'] and
        squeezing['restored_lane_index_input_control_and_frame_pointers_checked'] and
        squeezing['function']==n['executor'],'replayed absorption frame/readiness prerequisites')
    s.require(len(code)==1676 and code[648:920]==shape.shape(n),
              'complete saved one-rate absorption region')
    table=re.findall(r'^\.LJTI30_1:\s*\n((?:\s*\.long[^\n]*\n)+)',asm,re.M)
    s.require(len(table)==1 and re.findall(r'\.long\s+(\S+)',table[0])==
        [f'.LBB30_{v}-.LJTI30_1' for v in shape.TARGETS],'complete nine-part dispatch table')
    label='switch.table.'+n['executor']+'.104'
    raw=b''.join(v.to_bytes(8,'little') for v in model.framing.RATES)
    s.require(label in constants and constants[label]['bytes']==64 and
        constants[label]['sha256']==hashlib.sha256(raw).hexdigest(),'linked absorption rate table')
    rows=re.findall(r'^'+re.escape(label)+r':\n((?:\s*\.quad[^\n]+\n)+)',asm,re.M)
    s.require(len(rows)==1 and list(map(int,re.findall(r'\.quad\s+(\d+)',rows[0])))==list(model.framing.RATES),
        'assembly and linked absorption rates agree')
    checked=helpers.inspect(bodies,ir,n)
    actual=code[648:920]+code[631:637]
    samples=list(model.cases())[::11]
    for case in samples:model.check(actual,n,**case)
    return dict(function=n['executor'],region=[648,920],instruction_positions=272,
        helpers=checked,part_dispatch=list(shape.TARGETS),linked_rates=list(model.framing.RATES),
        saved_region_oracle_cases=len(samples),state_stride=200,frame_stride=156,
        readonly_bit_sources_and_two_byte_splits_checked=True,
        all_nine_parts_and_final_padding_bit_checked=True,
        cursor_block_count_and_absorbing_to_ready_transition_checked=True,
        proof_scope='one block; live/disjoint caller objects; synthetic secret bytes; no permutation',
        all_incoming_pointer_lifetimes_and_storage_nonoverlap_qualified=False,
        permutation_work_accounting_and_report_qualified=False,
        exception_and_private_frame_erasure_qualified=False)
