"""Metadata-preservation effects of already reviewed SHA-2 helper bodies.

These envelopes compose helper contracts; they do not infer safety from LLVM
readonly attributes. Their machine bodies/arguments are checked by the parent
batch-chain, primitive, transfer, authority and stack reviews.
"""
import re
import windows_enclave_sha2_field_ir as g
s=g.s


def length(arg,maximum=None):
    match=re.search(r' (-?\d+)$',arg)
    if match:value=int(match[1])
    else:
        match=re.search(r'range\(i64 0, (\d+)\)',arg)
        s.require(match is not None,'bounded field-effect length: '+arg)
        value=int(match[1])-1
    s.require(value>=0 and (maximum is None or value<=maximum),'field-effect length bounds')
    return value


def calls(record,known,lane):
    target,args,pointers=record['target'],record['args'],record['pointers']
    narrow=lane=='simd256';writes=[];kills=[];used=set()
    def effect(index,low,high):
        s.require(index in pointers,'field effect has an actual pointer argument')
        address=pointers[index];used.add(address)
        for root,a,b in known.get(address,[]):writes.append((root,a+low,b+high))
    def read(index):
        s.require(index in pointers,'field read has an actual pointer argument');used.add(pointers[index])
    if target.startswith('llvm.lifetime.'):
        s.require(len(args)==1 and target in ('llvm.lifetime.start.p0','llvm.lifetime.end.p0'),
                  'assigned field lifetime intrinsic')
        read(0)
        if '.end.' in target:kills=list(known[pointers[0]])
    elif target=='llvm.memcpy.p0.p0.i64':
        s.require(len(args)==4 and args[3]=='i1 false','reviewed field memcpy')
        effect(0,0,length(args[2]));read(1)
    elif target=='llvm.memset.p0.i64':
        s.require(len(args)==4 and args[1]=='i8 0' and args[3]=='i1 false','reviewed field memset')
        effect(0,0,length(args[2]))
    elif target.endswith('secret_memory18copy_secret_region'):
        s.require(len(args)==4,'reviewed field region copy')
        # Variable final-output widths are separately proven by finish/output
        # review; only the source can be a tracked workspace in those calls.
        if pointers[0] in known:
            extent=32 if narrow and pointers[0]=='%969' and args[1]=='i64 noundef %995' else length(args[1],128)
            effect(0,0,extent)
        else:read(0)
        read(2)
    elif target.endswith('secret_memory_volatile23zeroize_region_volatile'):
        s.require(len(args)==2,'reviewed field zeroizer');effect(0,0,length(args[1]))
    elif target.endswith('secret_memory22apply_secret_byte_mask'):
        s.require(len(args)==(2 if narrow else 3),'reviewed field mask');effect(0,0,1)
    elif target.endswith('Session14compress_bytes'):
        s.require(len(args)==4,'reviewed field vector session')
        effect(0,0,8);effect(0,16,17);effect(1,0,256);read(2)
        effect(3,0,2752 if narrow else 3264)
    elif re.search(r'6native6scalar$',target):
        s.require(len(args)==3,'reviewed field scalar compression')
        effect(0,0,32 if narrow else 64);read(1);effect(2,0,640)
    elif target.endswith('6engine7padding'):
        s.require(len(args)==3,'reviewed field padding')
        block,state,scratch=(4872,5128,4232) if narrow else (5348,5604,4708)
        effect(0,block,block+128);effect(0,state,state+(32 if narrow else 64))
        effect(0,scratch,scratch+640);effect(1,16,32);effect(2,16,24)
    elif target.endswith('Executor5check') or narrow and target.endswith('sha256_simd5check'):
        s.require(len(args)==1,'reviewed field executor check');read(0)
        writes.append(('authority',16,17))
    elif '9workspace' in target and target.endswith('Workspace4wipe') or (
            'drop_glue' in target and '9workspace' in target):
        s.require(len(args)==1,'reviewed field whole-workspace clear')
        effect(0,0,5280 if narrow else 5760);kills=list(known[pointers[0]])
    elif target.endswith('HardenedSha2Owner4wipe'):
        s.require(len(args)==1,'reviewed field scalar owner wipe');effect(0,0,1170)
    elif target.endswith('Workspace4wipe') and 'hardened_batch' in target:
        s.require(len(args)==1,'reviewed field CPU scratch wipe');effect(0,0,2752 if narrow else 3264)
    else:raise ValueError('unassigned metadata call effect: '+target)
    s.require(set(pointers.values()) & known.keys()<=used,'every metadata call argument assigned')
    return writes,kills
