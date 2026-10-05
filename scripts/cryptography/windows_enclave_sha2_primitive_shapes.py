"""Reviewed saved scalar SHA-2 primitive identities and instruction landmarks."""
import windows_enclave_sha2_state_review as state
import windows_enclave_bounded_sha256 as old

U32,U64 = state.ops.UPDATE32,state.ops.UPDATE64
F32,F64,WRITE = state.FINAL32,state.FINAL64,state.WRITE
S32,S64 = old.SCALAR,old.SCALAR.replace('compress32','compress64')
COPY,BYTES,MASK,PRED = old.COPY,old.BYTES,state.MASK,state.ops.MASK
MASKBYTE = '_RNvNtCsjNKEhcqdpKw_11brynja_core18secret_memory_mask9mask_byte'
PANIC = '_RNvNtNtCs8xEFJqa6dYS_4core9panicking11panic_const24panic_const_shr_overflow'
ROUND32,ROUND64 = state.ROUND[:-1]+'1',state.ROUND
EMPTY = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'
PINS = {n:old.PINS[n] for n in (U32,COPY,BYTES)} | {
    U64:(549,'a0d8b2bdb338b20a29a858b6bebc031ab5daf2de7fed3f3812aeea745d988dd7',
         'e6ac9add84024b3c7a4b1637136cf94666d6296639f7d1988275041875e0cf19'),
    F32:(674,'c24fb5131a3c6367bf62ebbab470fc44665d194d1bc433b0571b998d45592f3f',
         '4b754d90a80883fc98dd3e9d08c7604859691f2907b28394b768436c0ad2c8d0'),
    F64:(698,'4b61c7186928fbcdcc0801f0b3a9415188999e192daae07ed83e3099ede0ea99',
         'f70fce44067ce3eea0eb62f76bd2f813d0f66804d918644b845923dead51e93c'),
    WRITE:(120,'ede142b558e9f932d6c148871882cbf4136977cc5fe7ae8268112d6bdbb8e401',
           '608b2c0cb64fc6fcecc9bce4e492d575e066e88c0b6798c440270fb740d2337a'),
    S32:(482,old.PINS[S32][1],'261c79ee95f132f82d269584c72ae6342f6890de65eec25949ec56cbd26e8ab5'),
    S64:(545,'fc09e02bb2a3bb5d09c5c12db54044bc82a135819a98aa6478e8b1920085c5cb',
         'fb71fdfef9f777fd307be789ef25e37d2e833493aa8fd5fa64d9013ce2462f8c'),
    MASK:(5,'e8ebd827d1f36d7cfa5e5220610aa6370284d1589989363f48ac40166362d449',
          '05ce66c6d20e64a6ad96319d0deaa9bbb925f4b2cc085b5c89b69acbd1eddfd9'),
    MASKBYTE:(13,'a0b0ab8de40ec022f5e05286e3856a42c36aef7be325364afce4663273e3e350',EMPTY),
    PRED:(20,'abfd6d579afbeae45b4743454f4814533f72ce0edfef7bf25665e3c5201a4d45',EMPTY),
}
FRAMES = {U32:120,U64:120,F32:104,F64:104,WRITE:72,COPY:40,S32:16,S64:32}
LANDMARKS = {
    U64:((0,'4157415641554154565755534883ec38'),
         (36,'480fc94989d54889cd4c01c54889c34883d3004839cd4889d94819c10f92c14889d848c1e83d0f95c2b00108ca'),
         (100,'74474531f6ba800000004829ca4c0f43f24d39f44d0f42f4498d3c0e'),
         (288,'ba800200004c89f9e800000000ba800000004c89f1e800000000'),
         (459,'ba800200004c89f1e800000000ba800000004c89f9e800000000ba800000004889f1e800000000c6869104000000'),
         (510,'480fcb480fcd4889ae8804000048899e8004000031c04883c4385b5d5f5e415c415d415e415fc3')),
    F32:((0,'4157415641554154565755534883ec28'),
         (30,'c6819004000001440fb6b191040000488d99800300004981fe800000007761'),
         (124,'4080fd080f831502000041b08089e941d2e84c89e1b2ffe8000000004180fe377666'),
         (212,'ba800200004c89f9e800000000ba800000004c89f1e800000000'),
         (260,'480fcf4889beb8030000'),
         (332,'ba800200004c89f9e800000000ba800000004c89f1e800000000'),
         (594,'4c29ef4a8d0c2e4881c14004000031d24989f8e800000000'),
         (618,'ba800000004889f14883c4285b5d5f5e415c415d415e415fe900000000'),
         (647,'41c60424804180fe370f8708feffffe969feffffe8000000000f0b')),
    F64:((0,'4157415641554154565755534883ec28'),
         (38,'c6819004000001440fb6b191040000488db9800300004981fe80000000775f'),
         (129,'4080fd080f832802000041b08089e941d2e84a8d0c37b2ffe8000000004180fe6f766e'),
         (218,'ba800200004c89f9e800000000ba800000004c89f1e800000000'),
         (274,'490fcc480fcb48899ef80300004c89a6f0030000'),
         (351,'ba800200004889f9e800000000ba800000004889d9e800000000'),
         (616,'4983fd40771641b8400000004d29e84c01ef4889f931d2e800000000'),
         (644,'ba800000004889f14883c4285b5d5f5e415c415d415e415fe900000000'),
         (673,'c601804180fe6f0f87f6fdffffe95ffeffffe8000000000f0b')),
    WRITE:((0,'415741565657534883ec204889cf488b5c24704885db7434'),
           (33,'4c89c94889dae8000000004939de752c4889f14c89fa4989d8e8000000004889770848895f10c60700'),
           (74,'eb0566c70701034883c4205b5f5e415e415fc366c70701024889f14889da4883c4205b5f5e415e415fe900000000')),
    S64:((0,'41565657534c89c64889d74889cb4c8d3500000000'),
         (445,'4183c2084181fa800200000f8581feffff'),
         (497,'4531d24ac70416000000004183c2084181fa8002000075eb31c031c931d24531c04531c94531d24531db5b5f5e415ec3')),
    MASK:((0,'e900000000'),),
    MASKBYTE:((0,'0fb60120d04408c0880131c0c3'),),
    PRED:((0,'0fb6d2440fb6114121d20f94c00fb6c04531d2c3'),),
}


def render_plan(name,code):
    width,start = (4,384) if name == F32 else (8,406)
    # First word uses preserved state/output registers. Remaining words explicitly
    # address all seven state and output slots; COPY's equal-size contract holds.
    first = ('488d8e40040000ba0400000041b9040000004989d8e800000000' if width == 4 else
             '488dbe40040000ba0800000041b9080000004889f94d89f0e800000000')
    raw = bytes.fromhex(first)
    state.require(code[start-len(raw):start] == raw,'first rendered state word')
    for i in range(1,8):
        raw = (bytes.fromhex('4c8d86')+(1024+width*i).to_bytes(4,'little')+
               bytes.fromhex('488d8e')+(1088+width*i).to_bytes(4,'little')+
               b'\xba'+width.to_bytes(4,'little')+b'\x41\xb9'+width.to_bytes(4,'little')+b'\xe8'+bytes(4))
        state.require(code[start+30*(i-1):start+30*i] == raw,'remaining rendered state words')
    return [dict(source=1024+i*width,destination=1088+i*width,bytes=width) for i in range(8)]


def instructions(name,code):
    if name in (U32,COPY,BYTES,S32): old.instructions(name,code)
    else:
        for at,h in LANDMARKS[name]:
            raw = bytes.fromhex(h)
            state.require(code[at:at+len(raw)] == raw,'primitive instruction landmark')
    if name in (F32,F64): render_plan(name,code)


def final_contract(word_bits,used,tail_bits,output_bytes):
    """Review arithmetic under the private caller's admitted state, not an API."""
    state.require(all(type(v) is int for v in (word_bits,used,tail_bits,output_bytes)), 'integer final contract')
    state.require(word_bits in (32,64) and 0 <= used < word_bits*2 and 0 <= tail_bits < 8,
                  'valid buffer and partial-byte contract')
    state.require(output_bytes in (28,32) if word_bits == 32 else 1 <= output_bytes <= 64,
                  'caller-admitted output width')
    return dict(blocks=1 if used <= (55 if word_bits == 32 else 111) else 2,
                padding_bit=128 >> tail_bits,zero_tail_bytes=64-output_bytes,
                partial_pointer_present=tail_bits != 0)
