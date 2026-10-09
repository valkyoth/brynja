"""Public framing preparation only; absorption/worker cleanup remain open."""
import re
import windows_enclave_sha3_simd_frame_shape as shape
import windows_enclave_sha3_simd_frame_model as model
life,s=shape.life,shape.s


def inspect(bodies,asm,caller):
    n=shape.digest.helpers.names(bodies)
    s.require(caller['functions']['executor']==n['executor'] and
        caller['helpers']['geometry']['workspace_bytes']==5260 and
        caller['helpers']['geometry']==shape.digest.helpers.geometry(),
        'reviewed framing caller/workspace prerequisites')
    lines=life.code(bodies[n['executor']]);code=shape.shape(n)
    s.require(len(lines)==1676 and len(code)==385 and lines[69:454]==code,
              'complete saved public framing preparation region')
    table=re.findall(r'(?m)^\.LJTI30_0:\s*\n((?:\s*\.long[^\n]*\n)+)',asm)
    s.require(len(table)==1 and re.findall(r'\.long\s+(\S+)',table[0])==
        [f'.LBB30_{label}-.LJTI30_0' for label in shape.TARGETS],
        'all eight public framing identity jump targets')
    # Execute the actual saved region, not a separately maintained pseudocode
    # rendering. Exhaustive bounded campaign and mutants live in focused tests.
    samples=[([None]*4,1)]
    for tag in range(8):
        out=model.FIXED[tag] if tag<4 else 2048
        samples.append(([(tag,8192,255 if tag>=6 else 0,256 if tag>=6 else 0,out)]*4,1))
    for lanes,threshold in samples:model.check(lines[69:454],n,lanes,threshold)
    return dict(function=n['executor'],region=[69,454],instruction_positions=385,
        jump_targets=list(shape.TARGETS),saved_region_oracle_cases=len(samples),
        public_framing_fields_and_output_offsets_checked=True,
        no_secret_payload_mapped_in_model=True,
        model_scope='bounded resident metadata; modeled reviewed wipe/copy calls',
        inner_absorption_permutation_and_report_qualified=False,
        full_machine_pointer_lifetimes_qualified=False,
        private_frame_erasure_qualified=False)
