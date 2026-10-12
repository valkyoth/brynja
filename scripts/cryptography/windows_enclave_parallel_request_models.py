"""Bounded models of reviewed request branches, not native execution or OS proofs."""
import windows_enclave_parallel_request as request
import windows_enclave_parallel_lifecycle_models as lifecycle

require=request.require
MASK=(1<<64)-1


def decode(lane,operation,words):
    """Model actual unsigned masks/comparisons; tests use a declarative oracle."""
    require(lane in ('scalar','avx2'),'known wire layout')
    require(len(words)==(14 if lane=='scalar' else 16) and
        all(type(x) is int and 0<=x<=MASK for x in (*words,operation)),'u64 wire words')
    v,n,identity,block,budget,cl,ch,length,last,width,tail,terminal,source,reserved=words[:14]
    payload=(((operation-101)&MASK)<4) & ((13>>((operation-101)&15))&1)
    sized=(((operation-104)&MASK)<5) & ((23>>((operation-104)&31))&1)
    if (v!=(12 if lane=='scalar' else 18) or terminal>1 or tail>8 or last>8 or
        width>1024 or length>1024 or ((operation-109)&MASK)<MASK-8 or n==0 or reserved or
        (lane=='avx2' and (words[14]!=1 or words[15]))):return 3
    if ((payload and ((length==0)^(last==0))) or (not payload and (length|last)) or
        ((length==0)^(source==0))):return 3
    # Nine-entry read-only table destinations bound separately to COFF and PE.
    if operation in (100,106,108):
        if ((identity-1)&MASK)>3:return 3
    elif operation==103:
        if (last^((length!=0)<<3))|identity:return 3
    elif identity:return 3
    if operation in (100,108):
        if not block:return 3
    elif block|budget|cl|ch:return 3
    if ((not sized and (width|tail)) or (operation!=105 and terminal)):
        return 3
    if ((operation^105)|terminal)==0 and tail!=((width!=0)<<3):return 3
    if source+length>MASK:return 3
    if ((width==0) and tail!=0) or (width!=0 and tail==0):return 4
    return None


def export(lane,phase,previous,sequence,stored,requested,copy_ok=True,post_health=1,post_kernel=4):
    """Ordered ordinary-return effects, including possible output before failure.

    The fixed transport's success/failure is modeled, not its implementation.
    A failed copy is not presumed atomic or rolled back. Pre-copy admission uses
    a healthy authority; post-copy revocation is a separate observable boundary.
    """
    require(len(stored)==len(requested)==3,'identity/width/last shape')
    require(all(type(x) is int and 0<=x<=MASK for x in (*stored,*requested)),
        'bounded public shape fields')
    identity,width,last=requested
    require(1<=identity<=4 and width<=1024 and last<=8 and ((width==0)==(last==0)),
        'receiver-validated export shape')
    state=lifecycle.admission(lane,phase,(5,6),previous,sequence)
    events=['operation_admission'];copied=False
    error=state['error']
    if error is None:
        if identity!=stored[0]:error=0
        elif (width,last)!=stored[1:]:error=3
        else:
            events.append('fixed_output_copy')
            if not copy_ok:error=5
            else:
                copied=True
                if lane=='avx2':
                    events.append('post_copy_authority')
                    if post_health!=1 or post_kernel!=4:error=7
    if error is not None:
        events+=['quarantine_clear','failure']
        phase=7
    else:
        events+=['erase_1024_output','clear_shape']
        if phase==6:phase=4
        else:events.append('clear_owner');phase=0
        events+=['publish_phase','disarm_guard','success']
    return dict(error=error,phase=phase,events=events,successful_copy_observed=copied,
        failed_copy_may_have_written='fixed_output_copy' in events and not copy_ok,
        output_retracted=False)


def export_operands(bodies,lane):
    """Decode the original-owner field offsets and exact wipe extent independently."""
    code=bodies['receive'];operand=lifecycle.operand
    if lane=='scalar':
        identity=operand(code,0x510,'483b87',4)
        width=operand(code,0x521,'483b87',4)
        last=operand(code,0x52a,'4438bf',4)
        output=operand(code,0x533,'4c8dbf',4)
        count=operand(code,0x570,'ba',4)
        phase=operand(code,0x569,'0fb69f',4)
        require(code[0x575:0x578]==bytes.fromhex('4c89f9'),'wipe uses original retained buffer')
        require((identity,width,last,output,phase)==(0xd28,0xd40,0xd51,0x920,0xd50),
            'scalar export fields agree with original owner layout')
    else:
        identity=operand(code,0x2b2,'4c3bbf',4)
        width=operand(code,0x2bb,'483b9f',4)
        last=operand(code,0x2c4,'403aaf',4)
        count=operand(code,0x398,'ba',4)
        phase=operand(code,0x391,'0fb69f',4)
        require(code[0x39d:0x3a0]==bytes.fromhex('4889f9'),'wipe starts at original owner output')
        output=0
        require((identity,width,last,phase)==(0xc28,0xc40,0xc58,0xc5a),
            'AVX2 export fields agree with original placed owner layout')
        authority=operand(code,0x2e5,'488b8f',4)
        require(authority==0xc50,'post-copy check uses original borrowed authority')
    require(count==1024,'clear whole retained output, not merely requested width')
    return dict(identity=identity,width=width,last=last,phase=phase,
        output_region=[output,output+count],callee_and_original_owner_contracts_assumed=True)
