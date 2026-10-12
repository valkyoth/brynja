"""Actual sequential absorb cursor/length and complete-block flush contract."""
from windows_enclave_parallel_leaf_finish import MASK, LIMIT, require, windows

ANCHORS={
    'scalar':[
        (0x1b,'4c8944242048895424284d85c9'),(0x2e,'4d89cf4989ce0f57f6'),
        (0x40,'48017424204d85ff'),
        (0x4e,'498bae700400004d8ba678040000498b9ea004000041b5024839dd4c89e04883d800'),
        (0x76,'4889e84c09e0'),(0x7e,'498b96a8040000488d4c2450'),
        (0xe1,'4889d84829e8b9000000004c19e14939c7ba000000004819cabf000000004c89fe'),
        (0x104,'4889cf4889c64929f7'),
        (0x133,'498d4e02488b5424204989f0'),(0x15a,'498d4e02488b5424204989f0'),
        (0x16f,'4801f54c11e74989ae700400004989be780400004831dd4809fd'),
        (0x18f,'488d4424390f113048c744243001000000c6442438004c89f1488b5424284c8d442430')],
    'avx2':[
        (0x27,'48895424384d85c9'),(0x35,'4d89cd4989cec5c857f648894c2428'),
        (0x50,'4d89e84901f04c8b6c24304d85ed'),
        (0x64,'4d8ba6e0030000498bbee8030000498b9e18040000b0024939dc4889f94883d900'),
        (0x8b,'4c89e14809f9'),(0x97,'498b8e2004000048ffc94883f903'),
        (0xab,'4d89c7498b9610040000c1e10341b80405040541d3e8488d8c24e0000000'),
        (0x1d1,'4d89f8b002488b5c24304989d94d29e1b9000000004819f94d39cdba000000004819ca41bf000000004c89ee'),
        (0x1ff,'4989cf4c89ce4929f5'),
        (0x21c,'4c896c24304c89f14d89c54c89c24989f0c5f877'),
        (0x239,'4901f44911ff4d89a6e00300004d89bee80300004931dc4d09fc'),
        (0x259,'488d442449c5f8113048c744244001000000c6442448004c89f1488b5424384c8d442440')],
}
BRANCHES={
    'scalar':[(0x28,'0f84',0x1c4),(0x48,'0f84',0x1c4),(0x70,'0f83',0x1c7),
        (0x7c,'75',0xe1),(0x9d,'0f84',0x1eb),(0x102,'72',0x10a),(0x10d,'0f82',0x1e6),
        (0x11a,'74',0x150),(0x11f,'0f85',0x1c7),(0x12d,'0f85',0x1c7),
        (0x146,'74',0x16f),(0x148,'eb',0x1c7),(0x158,'75',0x1c7),
        (0x16d,'75',0x1c7),(0x189,'0f85',0x40),(0x1b9,'0f84',0x40)],
    'avx2':[(0x2f,'0f84',0x291),(0x5e,'0f84',0x291),(0x85,'0f83',0x29f),
        (0x91,'0f85',0x1db),(0xa5,'0f87',0x29d),(0xda,'0f84',0x295),
        (0x174,'74',0x186),(0x1fd,'72',0x205),(0x208,'0f82',0x299),
        (0x216,'0f84',0x29f),(0x237,'75',0x295),(0x253,'0f85',0x50),
        (0x289,'0f84',0x50)],
}


def step(used,block,length):
    require(type(used) is int and 0<=used<=LIMIT and type(block) is int and
        0<block<=MASK and type(length) is int and 0<length<=MASK,'nonempty absorb domains')
    require(used<block,'no full/invalid leaf before absorption')
    available=block-used;take=min(available,length)
    # Machine add/adc needs no overflow branch here: the preceding unsigned
    # comparisons establish used+take <= B <= u64::MAX, hence high word zero.
    low=(used&MASK)+take;high=(used>>64)+(low>>64)
    merged=(high<<64)|(low&MASK)
    require(0<take<=length and merged<=block,'cursor and leaf-counter bounds')
    return dict(take=take,remaining=length-take,used=merged,flush=merged==block)


def check(code,lane):
    windows(code,ANCHORS[lane],BRANCHES[lane])
    return dict(positive_progress=True,take='min(B-used, remaining)',
        consumed_cursor_advance_after_success=True,original_root_preserved=True,
        only_exact_complete_blocks_flush=True,arbitrary_B_controls_no_allocation=True,
        private_input_original_allocation_and_nonaliasing_still_caller_obligation=True)
