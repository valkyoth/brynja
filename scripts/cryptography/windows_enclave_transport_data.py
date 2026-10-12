"""Pinned read-only status inputs for the 08A SDK; not a full SDK taint proof."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import windows_enclave_sdk_diagnostic as diagnostic
import windows_enclave_sdk_return as pe

require = diagnostic.status.sdk.require
SPECS = {
    'formats': (0x20950,176,'d6cdebe1924ffea3e2968fc7857c4e1cceceee23af05e55303ae41022424ebc1'),
    'values': (0x20a00,8512,'a21ae4db2c2d18322b4eedea5365055e093ea130dbe495603aa858bf0b96012c'),
    'ranges': (0x22b40,2752,'cea467ed4370d53f7ef1ff0eb8b4cccaf9ed6928a9bd8f5491d7734ecc0d5edf'),
}


def check(parts):
    require(set(parts)==set(SPECS),'complete status-data population')
    for name,(_,size,expected) in SPECS.items():
        require(type(parts[name]) is bytes and len(parts[name])==size and
                hashlib.sha256(parts[name]).hexdigest()==expected,'reviewed status data '+name)
    for rva,expected in diagnostic.FORMATS.items():
        at = rva-SPECS['formats'][0]
        require(parts['formats'][at:at+len(expected)]==expected,'complete diagnostic string')
    entries = list(struct.iter_unpack('<IBBH',parts['ranges']))
    require(len(entries)==344 and entries[0][0]==0 and entries[-1][0]==0xffffffff,
            'inclusive search sentinel bounds')
    words = struct.unpack('<4256H',parts['values'])
    for start,count,width,index in entries:
        require(count>0 and start+count<=1<<32 and width in (1,2) and
                index+count*width<=len(words),'bounded complete status output range')
    require(all(a[0]+a[1]<=b[0] for a,b in zip(entries,entries[1:])),
            'sorted disjoint unsigned status intervals')
    return entries,words


def reference(data):
    diagnostic.inspect(data)  # Exact SDK file, code and fixed diagnostic strings.
    rows,_ = diagnostic.status.sdk.pe.linked(data)
    parts = {name:diagnostic.extract(rows,rva,size,False) for name,(rva,size,_) in SPECS.items()}
    check(parts)
    # A runtime byte comparison is valid only for relocation-free ranges.
    rva,size = pe.directory(data,5)
    relocations = pe.mapped(rows,rva,size)
    at = 0
    while at<len(relocations):
        page,block = struct.unpack_from('<II',relocations,at)
        require(block>=8 and block%2==0 and at+block<=len(relocations),'bounded relocation block')
        for index in range(at+8,at+block,2):
            entry, = struct.unpack_from('<H',relocations,index)
            kind,offset = entry>>12,entry&4095
            if kind==0: continue
            require(kind==10,'only reviewed AMD64 DIR64 SDK relocations')
            address = page+offset
            require(all(address+8<=start or start+length<=address
                        for start,length,_ in SPECS.values()),'no loader fixup in compared status data')
        at += block
    return parts


def convert(status,entries,words,linear=False):
    """Model of the pinned unsigned status conversion, not SDK execution."""
    require(type(status) is int and 0<=status<1<<32,'32-bit public OS status')
    if status==0: return 0,False
    if status==0x103: return 0x3e5,False
    if status & 0x20000000: return status,False
    if status & 0xff0000==0x70000 and status>>24 in (0x80,0xc0):
        return status&65535,False
    key = status&0xcfffffff if status>>28==0xd else status
    selected = None
    if linear:
        selected = next((row for row in entries if row[0]<=key<row[0]+row[1]),None)
    else:
        low,high = 0,len(entries)-1
        steps = 0
        while low<=high:
            require(0<=low<=high<len(entries) and steps<10,'bounded binary search')
            steps += 1
            middle = (low+high)//2
            row = entries[middle]
            if key<row[0]: high=middle-1
            elif key-row[0]>=row[1]: low=middle+1
            else:
                selected=row
                break
    if selected is None:
        return (key&65535,False) if key&0xffff0000==0xc0010000 else (0x13d,True)
    start,_,width,index = selected
    at = index+(key-start)*width
    return words[at] if width==1 else words[at]|(words[at+1]<<16),False


def inspect(data):
    parts = reference(data)
    entries,words = check(parts)
    return dict(schema=1,status='SAVED_SDK_READ_ONLY_STATUS_INPUTS',
        image_sha256=hashlib.sha256(data).hexdigest(),entries=len(entries),output_words=len(words),
        regions={name:dict(rva=rva,bytes=size,sha256=sha) for name,(rva,size,sha) in SPECS.items()},
        only_variadic_status_format='one 32-bit hexadecimal status; two strings have no conversion',
        loaded_identity_proven=False,os_return_registers_qualified=False,
        formatter_and_exception_transitive_payload_proof=False,whole_image_qualified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    args=parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes()),indent=2))
