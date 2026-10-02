#!/usr/bin/env python3
"""Local capture-encoder and completeness regressions; not VBS execution."""
import copy
import struct
import windows_enclave_sha256_simd_native as native

def rejected(call):
    try: call()
    except (ValueError,RuntimeError): return
    raise AssertionError('Invalid native evidence accepted')

def main():
    rows=native.cases()
    assert len(rows)==52
    assert {i for row in rows for i,_,_ in row[0]} == {224,256}
    for layout,data,expected in rows:
        assert len(expected)==256 and len(data)==8
        pointers=[0x10000+0x1000*lane for lane in range(8)]
        for op in (100,101,102):
            words=native.words_for(op,37,layout,pointers)
            assert len(struct.pack('<36Q',*words))==288
            assert words[:4]==[21,37,1000 if op==100 else 0,2]
            for lane,(identity,length,last) in enumerate(layout):
                assert words[4+4*lane:8+4*lane]==[
                    identity if op!=102 else 0,length if op==100 else 0,
                    last if op==100 else 0,pointers[lane] if op==100 else 0]
                assert len(data[lane])==length and data[lane][-1]&((1<<(8-last))-1)==0
    assert native.copy_counts(100,None)==[1,8,0,0]
    assert native.copy_counts(101,None)==[1,0,1,0]
    assert native.copy_counts(102,None)==[1,0,0,0]
    for lane in range(8): assert native.copy_counts(100,f'payload-{lane}')==[1,lane,0,1]
    assert native.copy_counts(100,'header-copy')==[0,0,0,1]
    assert native.copy_counts(101,'output-copy')==[1,0,0,1]
    for fault in ('version','sequence','route','identity','length','last'):
        assert native.copy_counts(100,fault)==[1,0,0,0]
    for fault in ('budget','bits'): assert native.copy_counts(100,fault)==[1,8,0,0]
    good=dict(comparisons=53,lane_comparisons=424,calls=[{}]*302,deleted=True,
        production_qualified=False,private_worker_enclave_execution=True,multi_message_simd=True)
    native.validate_completion(good)
    for key,value in dict(comparisons=52,lane_comparisons=416,calls=[{}]*301,deleted=False,
        production_qualified=True,private_worker_enclave_execution=False,multi_message_simd=False).items():
        bad=copy.deepcopy(good); bad[key]=value
        rejected(lambda: native.validate_completion(bad))
    print('SIMD native capture: 52 eight-lane encodings, copy receipts and 7 completeness regressions PASS')

if __name__=='__main__': main()
