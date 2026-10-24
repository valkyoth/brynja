"""Bind compiled worker selection inputs to the verified launch envelope.

This is operand/storage provenance, not the later keyed-owner lifecycle or
MD5 lane construction. It composes with the host capture and worker envelope.
"""
import re

import legacy_hmac_hosted_authority as authority

syntax, require, V = authority.syntax, authority.require, authority.V


def read_capture(t, loads, offset, dtype):
    require(offset in loads, 'legacy captured reference absent')
    ref_site, reference = loads[offset]
    reads = [(name, point) for name, (rhs, point) in t.defs.items()
             if re.match('load ' + dtype + ', ptr ' + re.escape(reference) + ',', rhs)]
    require(len(reads) == 1, 'legacy captured reference read population changed')
    value, site = reads[0]
    require(t.before(ref_site, site) and t.before(site, t.keyed), 'legacy captured reference read too late/early')
    # Captured immutable scalar references cannot acquire writes or escaping
    # aliases in the worker. Merely matching the selected load is insufficient.
    for label, lines in t.graph.items():
        for index, line in enumerate(lines):
            if reference not in re.findall(V, line) or (label, index) in (ref_site, site):
                continue
            nonnull = re.fullmatch('(' + V + ') = icmp ne ptr ' + re.escape(reference) + ', null', line)
            if nonnull:
                require(index + 1 < len(lines) and re.fullmatch(r'(?:tail )?call void @llvm.assume\(i1 '
                        + re.escape(nonnull[1]) + r'\)', lines[index + 1]), 'legacy reference assumption changed')
                continue
            require(re.fullmatch(r'(?:tail )?call void @llvm.assume\(i1 true\) \[ "nonnull"\(ptr '
                                 + re.escape(reference) + r'\) \]', line),
                    'legacy captured reference escaped or modified')
    return value, site


def check(transfer, envelope):
    t = transfer
    call = next(args for _, args, point in t.calls if point == t.keyed)
    destination = t.pointer(syntax.operand(call[0]), t.keyed)
    size = 912 if t.identity == 'sha1_compiled' else 24
    require(destination and destination[1] == 0 and t.allocs[destination[0]] == size
            and destination[0] not in (t.owner, t.result), 'legacy keyed result allocation changed')
    loads = envelope['loads']
    if t.identity == 'sha1_compiled':
        for index, offset in ((2, 24), (3, 32)):
            require(offset in loads and call[index].split()[-1] == loads[offset][1]
                    and t.before(loads[offset][0], t.keyed), 'legacy keyed key operand changed')
        width, _ = read_capture(t, loads, 16, 'i64')
        require(call[4].split()[-1] == width, 'legacy tag width substituted')
    else:
        require(64 in loads and call[2].split()[-1] == loads[64][1]
                and t.before(loads[64][0], t.keyed), 'legacy MD5 selection tag width changed')
    return destination
