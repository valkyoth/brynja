"""Byte-origin model for the separately checked scalar finish_setup body.

This is a bounded symbolic transfer model, not an x86 emulator. Its schedule
is hand-transcribed from the complete instruction contract. Runtime memcpy,
memset, volatile wipe and ABI preservation are explicit callee assumptions.
"""
from windows_enclave_sha3_batch_lifecycle import s


def schedule(tag):
    s.require(tag in (7,8),'scalar setup has two concrete variants')
    head,tail,bulk=(64,40,3432) if tag==7 else (80,44,4420)
    # Transfers include overlapping scalar/vector stores. A source must remain
    # physically live; logical enum replacement alone does not retire its bytes.
    return [
        ('copy','owner',16,'frame',1296,1136),
        ('zero','owner',16,1),
        ('copy','owner',32,'frame',176,1120),
        ('copy','frame',244,'saved',0,1),
        ('copy','owner',101,'frame',head,8),('copy','owner',108,'frame',head+7,8),
        ('copy','owner',116,'frame',128,16),('copy','owner',148,'frame',bulk,988),
        ('copy','owner',1137,'frame',tail,2),('copy','owner',1139,'frame',tail+2,1),
        ('zero','frame',244,1040),
        ('copy','frame',1284,'saved',1,1),
        ('zero','frame',176,64),('zero','frame',240,1),('zero','frame',243,1),('zero','frame',1284,1),
        ('copy','frame',head,'frame',96,8),('copy','frame',head+7,'frame',103,8),
        ('copy','frame',128,'frame',111,16),
        ('copy','frame',96,'frame',144,16),('copy','frame',111,'frame',159,16),
        ('copy','frame',head,'frame',48,8),('copy','frame',head+7,'frame',55,8),
        ('copy','frame',bulk,'frame',2444,988),
        ('copy','frame',tail,'frame',36,2),('copy','frame',tail+2,'frame',38,1),
        ('copy','saved',0,'owner',18,1),('copy','frame',144,'owner',19,16),
        ('copy','frame',159,'owner',34,16),('copy','saved',0,'owner',50,1),
        ('copy','frame',48,'owner',51,8),('copy','frame',55,'owner',58,8),
        ('copy','frame',2444,'owner',66,988),('copy','saved',1,'owner',1054,1),
        ('copy','frame',38,'owner',1057,1),('copy','frame',36,'owner',1055,2),
    ]


def replay(tag,steps=None):
    original=[('owner',at) for at in range(2400)]
    memory={'owner':original.copy(),'frame':[None]*5408,'saved':[None]*2}
    # Operation result occupies [1296,1312) before this schedule. Both fields
    # have already moved into preserved registers before the old-state copy.
    def region(name,at,size):
        s.require(name in memory and 0<=at and 0<size and at+size<=len(memory[name]),'bounded moved-state region')
        s.require(name!='frame' or at>=32,'no secret transfer into outgoing callee home area')
        return memory[name]
    for step in schedule(tag) if steps is None else steps:
        if step[0]=='zero':
            _,name,at,size=step;target=region(name,at,size);target[at:at+size]=[0]*size
        else:
            s.require(step[0]=='copy','known moved-state operation')
            _,src,start,dst,end,size=step
            source=region(src,start,size);target=region(dst,end,size)
            s.require(src!=dst or start+size<=end or end+size<=start,'no overlapping memcpy/source-destination region')
            values=source[start:start+size]
            s.require(None not in values,'no read from uninitialized moved-state byte')
            target[end:end+size]=values
    # Independently described output owner: domain/length metadata copied into
    # the returned cSHAKE wrapper plus all 988 bulk bytes and trailing flags.
    expected=original[100:132]+original[100:116]+original[148:1136]+original[1140:1141]+original[1137:1140]
    s.require(len(expected)==1040 and memory['owner'][18:1058]==expected,'every installed streaming-owner byte has exact origin')
    s.require(memory['frame'][244:1284]==[0]*1040 and memory['frame'][240]==0,
        'consumed setup owner and pending byte cleared in their actual temporary')
    s.require(memory['frame'][1296:2432]==original[16:1152],
        'old-state copy remains physically live and is not falsely reported erased')
    s.require(memory['owner'][16]==0,'old destination tombstoned before installation of the new tag')
    return dict(variant=tag,result_variant=tag-2,installed_owner_bytes=1040,
        all_installed_bytes_have_exact_origin=True,source_reads_initialized_and_bounded=True,
        copy_source_destination_nonoverlap=True,temporary_owner_cleared_bytes=1040,
        old_state_copy=[1296,2432],setup_copy=[176,1296],common_payload=[2444,3432],
        selected_bulk_payload=[3432,4420] if tag==7 else [4420,5408],
        old_state_copy_erased=False,temporary_copies_fully_erased=False,
        runtime_copy_and_wipe_semantics_assumed=True)
