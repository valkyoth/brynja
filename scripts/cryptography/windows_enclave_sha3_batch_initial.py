"""Explicit saved AVX2 constructor reuse, including the renamed width table.

This reuses a replayed streaming constructor, not its batch caller lifetimes.
Runtime memcpy/memset and enclosing private-window retirement remain separate.
"""
import hashlib
import windows_enclave_sha3_batch_lifecycle as life

s=life.s
NAME='_RNvMs2_CscBEH4D3OuJh_22sha3_accelerated_stateNtB5_5State7initial'
TABLE='switch.table.'+NAME
OLD=TABLE+'.216'
NEW=TABLE+'.189'


def rebind(functions,prior,ir,prior_ir,exact,old_constants,constants):
    s.require(NAME in functions and NAME in prior,'both emitted initial constructors')
    code,refs,kind=functions[NAME];old_code,old_refs,old_kind=prior[NAME]
    s.require(code==old_code and kind==old_kind,'complete constructor bytes and extent kind')
    renamed=[r|{'symbol':NEW} if r['symbol']==OLD else r for r in old_refs]
    s.require([r for r in old_refs if r['symbol']==OLD]==[
        dict(offset=901,symbol=OLD,trailing=0,addend=0)],'one exact prior width-table operand')
    s.require(refs==renamed,'only the enumerated width-table relocation may change')
    s.require(life.reuse.abi(ir,NAME)==life.reuse.abi(prior_ir,NAME),
              'complete resolved constructor LLVM ABI')
    children={r['symbol'] for r in refs if r['symbol'] in functions}
    s.require(children and children<=set(exact),'constructor kernel and wipes replay exact helper review')
    data={r['symbol'] for r in refs}-{r['symbol'] for r in refs if r['symbol'] in functions}-{'memcpy','memset'}
    s.require(len(data)==8 and {TABLE,NEW}<=data,'six KAT constants and two constructor tables')
    result={}
    for name in sorted(data):
        old=OLD if name==NEW else name
        s.require(old in old_constants and name in constants,'both linked immutable constructor constants')
        before,after=old_constants[old],constants[name]
        s.require(all(key in before and key in after for key in ('bytes','sha256','rva')),
                  'bound complete constant metadata')
        s.require(before['bytes']==after['bytes'] and before['sha256']==after['sha256'],
                  'constructor constant bytes agree across linked images')
        if name in (TABLE,NEW):
            values=[144,136,104,72,168,136,168,136] if name==TABLE else [28,32,48,64]
            raw=b''.join(n.to_bytes(8,'little') for n in values)
            s.require(after['bytes']==len(raw) and after['sha256']==hashlib.sha256(raw).hexdigest(),
                      'independent algorithm rate/output-width definition')
        result[name]=dict(prior_name=old,**after)
    return dict(function=NAME,body_bytes=len(code),relocations=len(refs),
        exact_code_extent_and_abi=True,explicit_renamed_reference=[OLD,NEW],
        linked_constants=result,reviewed_callees=sorted(children),
        constructor_semantics_reused=True,batch_caller_lifetimes_qualified=False,
        private_frame_erasure_qualified=False,shared_runtime_completion_package=8)
