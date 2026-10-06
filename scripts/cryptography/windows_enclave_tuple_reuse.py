"""Reproduce earlier reviews before accepting TupleHash helper reuse."""
import windows_enclave_kmac_chains as c

require=c.require
s=c.shapes


def abi_changes(changed,lane):
    expected={
        s.CORE+'17secret_memory_xor8xor_bits':('range(i32 0, 9) %3','range(i32 0, 8) %3'),
        s.CORE+'13secret_memory20xor_secret_byte_bits':('range(i8 0, 9) %4','range(i8 0, 8) %4'),
        '_RNvMNtCs58M5yX2Qwr5_16brynja_hash_sha310bit_stringNtB2_16Fips202BitString3new':
            ('range(i64 0, 1025) %2','range(i64 0, 65536) %2')}
    if lane=='avx2':
        expected['_RNvMs2_CscBEH4D3OuJh_22sha3_accelerated_stateNtB5_5State6update']=(
            'range(i64 0, -9223372036854775808) %2','range(i64 0, 2305843009213693952) %2')
    require(set(changed)==set(expected),'only reviewed TupleHash helper ABI differences')
    for name,(before,after) in expected.items():
        old,new=changed[name]['prior_abi'],changed[name]['current_abi']
        require(old.count(before)==1 and new==old.replace(before,after),
                'only explicit parameter-range change')
    return expected


def bounded_bits(bodies,ir):
    name=s.one(bodies,r'Fips202BitString3new$')
    require('range(i64 0, 65536) %2' in c.reuse.abi(ir,name),'bounded private byte count')
    s.sequences(bodies[name],[
        'subb $1, %r10b|setb %al|xorl %r11d, %r11d|cmpb $8, %r10b|setb %r11b|'
        'testq %r8, %r8|cmovel %eax, %r11d|testb %r11b, %r11b|je .B1',
        'testq %r8, %r8|je .B3|movzbl %r9b, %eax|leaq (%rax,%r8,8), %rsi|addq $-8, %rsi',
        'callq '+s.CORE+'13secret_memory24secret_byte_mask_is_zero'])
    # For the admitted positive lengths and final width 1..8 this address-free
    # bit count is in 1..524280, so the emitted LEA cannot overflow u64.
    require((65535-1)*8+8 < 2**64,'bounded widened bit-count arithmetic')
    return dict(maximum_private_bytes=65535,maximum_bits=524280,
                public_worker_input_limit=1024,not_a_foreign_unbounded_entry=True)


def inspect(base,root,lane,functions,ir,bodies,prior_report):
    _,data,_,_,old_ir,_=c.load(base,root,lane,c.specification(c.SPEC.read_bytes())[lane])
    old=c.previous.inventory(data)
    reused,changed=c.reuse.exact_reuse(functions,old,ir,old_ir)
    require(len(reused)==(24 if lane=='scalar' else 23),'exact same-name helper population')
    changes=abi_changes(changed,lane)
    renamed={}
    roles=[(r'worker7BuffersE',r'worker7BuffersE')]
    if lane=='avx2':
        roles += [(r'workerNtB2_7Buffers5clear$',r'workerNtB2_7Buffers5clear$'),
                  (r'15check_authority$',r'15check_authority$'),
                  (r'drop_glueNtCsc.*sha3_accelerated_state5StateE',
                   r'drop_glueNtCsc.*sha3_accelerated_state5StateE')]
    for current_pattern,old_pattern in roles:
        name=s.one(functions,current_pattern);previous=s.one(old,old_pattern)
        require(functions[name]==old[previous],'renamed complete helper body and references')
        actual=c.reuse.abi(ir,name);expected=c.reuse.abi(old_ir,previous).replace('@'+previous+'(','@'+name+'(')
        require(actual==expected,'renamed helper complete ABI')
        renamed[name]=dict(prior_name=previous,abi_sha256=c.digest(actual.encode()))
    return dict(prior_route=prior_report['route'],prior_image_sha256=prior_report['image_sha256'],
        reproduced_prior_private_chain=True,exact_body_reference_abi_reuse=reused,
        explicit_abi_changes={n:dict(before=a,after=b) for n,(a,b) in changes.items()},
        abi_change_context='XOR destination and absorb length narrow; bit-string length separately bounded',
        renamed_helpers=renamed,bit_string=bounded_bits(bodies,ir),
        all_current_callee_addresses_rebound=True)
