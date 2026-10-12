"""Sequential CV production/commit/erasure landmarks in actual bound bodies."""
from windows_enclave_parallel_leaf_finish import MASK, LIMIT, require, windows

# Before any CV exists: reject used>B, empty leaf and tail at a full block;
# checked increment. Then a 64-byte local CV, 32/64-byte selected output,
# successful root update before leaf retirement/count commit, full CV clearing.
ANCHORS={
    'scalar':[
        (0x13,'4c8b99700400004c8b9178040000488bb1a0040000b0024531c94c39de4d19d1'),
        (0x49,'4c89df4c09d7410f94c14d8b70104d85f60f94c34939f34983da00410f92c24c09f7'),
        (0x72,'488b99800400004c8bb1880400004883c3014983d600'),
        (0x154,'4889f10f57c00f294424600f294424500f294424400f29442430488b86a804000048ffc831f648a9fdffffff400f95c6c1e6054883c620c644242001488d5424304889cf4989f041b108'),
        (0x1a7,'488d4c2430ba4000000089c3e80000000089d8'),
        (0x1e0,'4c89f94883c102488d5424304989f0'),
        (0x202,'4883c102488d5424304989f0'),
        (0x21b,'4889fe4881c7700400004889f1e800000000c60600ba100000004889f9e8000000004c89b68804000048899e80040000488d4c2430ba40000000e800000000b0ff')],
    'avx2':[
        (0x34,'4889d64c8b89e0030000488b91e80300004c8b911804000040b70231c04d39ca4819d0'),
        (0x6f,'4d89ce4909d60f94c04d8b78104d85ff410f94c34d39d14883da000f92c24d09fe'),
        (0x97,'4c8ba1f00300004c8ba9f80300004983c4014983d500'),
        (0xdc,'c5f857c0c5fc2983e0000000c5fc2983c0000000498b862004000048ffc84531ff48a9fdffffff0f95c040b702'),
        (0x113,'4188c741c1e7054983c720c644242001488d93c00000004d89f841b108c5f877'),
        (0x144,'488d8bc0000000ba40000000c5f877e800000000'),
        (0x296,'488d93c00000004889f14d89f8'),
        (0x2b3,'4c89f0498db6e00300004183beb0030000ff740b4c89f1e8000000004c89f048c780b0030000ffffffffba100000004889c74889f1e8000000004c89aff80300004c89a7f0030000488d8bc0000000ba40000000e80000000040b7ff')],
}
BRANCHES={
    'scalar':[(0x33,'73',0x49),(0x6b,'74',0x35),(0x70,'74',0x35),(0x88,'0f82',0x261),
        (0x14e,'0f85',0x35),(0x1a5,'74',0x1c7),(0x1ba,'e9',0x35),
        (0x1ce,'74',0x1f6),(0x1d5,'75',0x1a7),(0x1de,'75',0x1a7),
        (0x1f4,'eb',0x213),(0x200,'75',0x1a7),(0x219,'75',0x1a7),
        (0x25c,'e9',0x35),(0x263,'e9',0x35)],
    'avx2':[(0x57,'73',0x6f),(0x90,'74',0x59),(0x95,'74',0x59),(0xad,'0f82',0x314),
        (0xc2,'74',0x59),(0xd7,'75',0x59),(0x111,'74',0x144),
        (0x13b,'0f84',0x289),(0x158,'e9',0x59),(0x290,'0f84',0x144),
        (0x2ad,'0f85',0x144),(0x2c5,'74',0x2d2),(0x30f,'e9',0x59),(0x317,'e9',0x59)],
}


def admitted(used,block,tail_bits,leaves,identity):
    require(all(type(n) is int and 0<=n<=LIMIT for n in (used,leaves)) and
        type(block) is int and 0<block<=MASK and type(tail_bits) is int and
        0<=tail_bits<8 and type(identity) is int and 1<=identity<=4,'typed leaf domains')
    require(used<=block and (used!=0 or tail_bits!=0) and
        (tail_bits==0 or used<block),'leaf flush shape')
    require(leaves<LIMIT,'leaf increment cannot wrap')
    return dict(next_leaves=leaves+1,cv_bytes=32 if identity in (1,3) else 64)


def geometry(lane):
    # Frame-local CV spans only. Construction temporaries can reuse this range
    # before CV initialization. Their old copies and callers require pass 2's
    # remaining storage composition and package 8's complete window erasure.
    if lane=='scalar':
        return dict(base='RSP after sub 2328',offset=48,bytes=64,
            first_live_offset=0x15a,last_normal_use_offset=0x255,
            cleanup_offsets=[0x1b3,0x255],funclet=None)
    require(lane=='avx2','known sequential route')
    return dict(base='RBX = align_down(RSP after sub 3096,32)',offset=192,bytes=64,
        first_live_offset=0xe0,last_normal_use_offset=0x307,
        cleanup_offsets=[0x153,0x307],funclet='Input::flush dtor$20',
        handler_address='align_down(establisher,32)+192')


def check(code,lane):
    windows(code,ANCHORS[lane],BRANCHES[lane])
    return dict(cv_bytes=64,selected_bytes=[32,64],terminal_leaf_squeeze=True,
        root_update_precedes_leaf_count_commit=True,
        normal_return_cv_erasure=True,geometry=geometry(lane),
        all_state_moves_individually_erased=False,outer_lifetime_composition_pending=True)
