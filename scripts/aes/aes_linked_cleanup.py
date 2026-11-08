"""Exact caller-owned AES Drop paths, including emitted unwind landing pads.

The external unwinder/loader and exception-table interpretation remain trusted;
actual caller unwinds exercise dispatch separately from this instruction review.
"""
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('aes_cleanup_image', Path(__file__).with_name('aes_linked_mix.py'))
image_review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image_review)
require = image_review.require
WIDTHS = {'key128': 16, 'key192': 24, 'key256': 32,
          'cached128': 176, 'cached192': 208, 'cached256': 240}


def candidates(table):
    selected = {}
    owner = r'(14cleanup_key|17cleanup_cached)(128|192|256)'
    legacy = r'_ZN9lifecycle' + owner + r'17h[0-9a-f]{16}E'
    current = r'_RNvC\w+_9lifecycle' + owner
    for line in table.splitlines():
        if 'cleanup_' not in line or '9lifecycle' not in line:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized cleanup symbol row')
        address, size, name = match.groups()
        row = (name, int(address, 16), int(size, 16))
        match = re.fullmatch(legacy, name) or re.fullmatch(current, name)
        require(match is not None and row[2] > 0, 'unrecognized/empty cleanup symbol')
        role = ('key' if match[1] == '14cleanup_key' else 'cached') + match[2]
        require(role not in selected, 'duplicate cleanup role')
        selected[role] = row
    require(set(selected) == set(WIDTHS), 'cleanup population changed')
    ordered = sorted(selected.values(), key=lambda row: row[1])
    require(all(a[1] + a[2] <= b[1] for a, b in zip(ordered, ordered[1:])), 'overlapping cleanup symbols')
    return selected


def resume_target(plt, relocations, image):
    """Bind the imported resume entry to its actual PLT/GOT relocation.

    This identifies the runtime dependency, not an approval of its implementation.
    Only the observed ELF x86_64 lazy-PLT layout is admitted.
    """
    require(plt.count('file format elf64-x86-64') == 1
            and plt.count('Disassembly of section .plt:') == 1, 'unexpected PLT output')
    headers = re.findall(r'^([0-9a-f]+) <([^>]+)>:$', plt, re.M)
    resume = [int(a, 16) for a, n in headers if n == '_Unwind_Resume@plt']
    base = [int(a, 16) for a, n in headers if n == '.plt']
    require(len(resume) == len(base) == 1, 'missing/ambiguous resume PLT entry')
    slots = []
    for line in relocations.splitlines():
        if 'R_X86_64_JUMP_SLOT' not in line:
            continue
        match = re.fullmatch(r'([0-9a-f]+)\s+R_X86_64_JUMP_SLOT\s+(\S+)', line)
        require(match is not None, 'unrecognized PLT relocation')
        slots.append((int(match[1], 16), match[2]))
    indices = [i for i, (_, name) in enumerate(slots) if name == '_Unwind_Resume']
    require(len(indices) == 1 and len({a for a, _ in slots}) == len(slots),
            'missing/ambiguous resume relocation')
    address, index = resume[0], indices[0]
    loads = image_review.segments(image)
    pos = image_review.file_offset(loads, address, 16, 5)
    code = image[pos:pos + 16]
    require(code[:2] == b'\xff\x25' and code[6:7] == b'\x68' and code[11:12] == b'\xe9'
            and address + 6 + int.from_bytes(code[2:6], 'little', signed=True) == slots[index][0]
            and int.from_bytes(code[7:11], 'little') == index
            and address + 16 + int.from_bytes(code[12:16], 'little', signed=True) == base[0],
            'resume PLT encoding/relocation mismatch')
    image_review.file_offset(loads, slots[index][0], 8, 6)
    image_review.file_offset(loads, base[0], 16, 5)
    return '_Unwind_Resume@plt', address, 16


def callback(compiler, panic):
    return 'callq *(%rsp)' if (compiler, panic) in (('1.90.0', 'abort'), ('1.99.1', 'unwind')) else 'callq *8(%rsp)'


def policies(count, size, calls, rows):
    return {role: dict(instructions=count, symbol_bytes=size, constant_loads=0,
                       calls=calls, indirect_calls=1, text_sha256=text, encoding_sha256=encoding)
            for role, text, encoding in rows}


# Four complete streams reviewed explicitly. Width varies only in the public
# completion marker (fixed owner storage size). No automatic refresh path.
POLICY = {
    ('1.90.0', 'abort'): policies(28, 115, 2, [
        ('key128', 'cf194d35552458431ab887a51f639a276196810b9549f99206545f8154aa2773', '3983a00e21ed903fcaeeb57d1c4bc0016838a800334e896a8cfadea59f55e1b5'),
        ('key192', '6e3fddb005717eeab1a4aaab11db521bc2ed4fac5341c7668472e6e2ade8b72a', '8cd4b84ec78e78f4a8fbfbedce16c63281c4e0ecf82eb7c68ba4cbf95e318292'),
        ('key256', 'b62b256f9406516ad3d21a6226ebcdfc3c8cdb6348d1021255af14dd8517a7c2', '7dba0f988aec28a61dd3e7e98ed4c5cfd0ea977fbe002a27580b334ee170c95a'),
        ('cached128', '2425fd7e5b67afb7afa4e831417f4067cd1629d359614622c024e82bae72fb4d', '15466d5053d247cc439a48915612eca2dd728e458a80168a3be2446dc5aa0426'),
        ('cached192', '53c0f65e413e4209a07d4fadd172ba2c209c7457a962927455bceddee2641b3c', '9ced45aeb99dd5aece83b0414bf9f58e9202275fdfb64b6715d93311ae4ad06b'),
        ('cached256', '9e638f1a99683b58e987a57d7f1213eaaeaf02891c588ee3a8fab8ccc7ae9f2a', 'b57a0624ca003fd75a395c3e8127df5b9dff3fd8ed73945999f24a052fdcb0b5'),
    ]),
    ('1.90.0', 'unwind'): policies(48, 198, 6, [
        ('key128', 'e9734a53b5da45e6eac007ce9548eeb438b6d36d2db4551d0e0660349613c40b', '6d9821659883263e81c52b87f47b782006995e43375f705fde84104850950831'),
        ('key192', '817543eb9fd8bbc9503e5c69ea7259581fe5b6f0d3fbaca1b770e9991fa76e3c', 'c480c8738e342a9ac4cad6cf990f0b77cba3f0c931a29d404e7e2270ccb0b154'),
        ('key256', '0b28e39ce3c57e3ef78bd178f92c56e0e09864df3e0e644fa3ddad44c8d71541', '1d49ee4c508de375de4111dececd4445cfb442f29a4edd1fe6356cbae01ad6d4'),
        ('cached128', '057dcfd9ae831350c3017f3ab41b22ceec2f1734440f84d255a7fbf0c4fb6636', 'd905b3f16231338a08839cef09aa3d05d3e923b7725e37fb40239b18b1621627'),
        ('cached192', 'd740ec262938913f20d8f2b15c6ce21049b46ce906ed2979d71d8e0fa28cb534', 'af983102558ec16b99c8e600bd1e3b49045642ec7274ce6d94ff6ac22fab4146'),
        ('cached256', '81b6662ffe2c55fb50b1e73ff60365323b214350988abe74d2c85e0533d63ed8', '6fcddbb225f913395751b0e0ada296b2f11f311810c15a16300bfd450c899cf9'),
    ]),
    ('1.99.1', 'abort'): policies(28, 127, 2, [
        ('key128', '15b0f58fad2ebd908db8c325b6342fb2d09da890a9b07018906b28438398d30f', '5e1ddea5790e4181e9170b09bba3b21a75fe2d0d69bd840d494c9f7e680cc817'),
        ('key192', '8c78308e3ace133284f8ac64e1e3354473bdceb5162b88386bd71e305892346f', '0d74b775fb7c5c3135b2d73c452ef9f420ca6497670543192641bd97d54d5cdf'),
        ('key256', 'cb1844634a936daf969a5a1cef0cca4c1acfda9ebcd519227f13df82829f1f0a', 'aa04c7bb604ca21803d95b4bb2eee7f5fa9702f9f73218dd55ea4f7d42c90b5d'),
        ('cached128', '35bd187fbab7e9f2aec9d8d703adf70a452c68b7e1453c8b60f19e25fa704099', '6bc78d523dd4d64435fcf00ce6fd1056c4f883603d71b510abc4fe2a13c0b422'),
        ('cached192', 'c2f8200d8fe12975eccc61f61869e1d3176d6024c6d35837c85c2cbfcdf0a236', 'b1c2d969ac163ca3e1445164592fb266bc7ecdc86a92bd7e7bb02bc55669613c'),
        ('cached256', '8f15006ceb5605f5eaa7b8f6c222f2a5b694aa62f6c06579d6c8fe7af41ef05b', '4a1acf1a25e8935fcd9534acd7fa569c0e42a348de0defbf52fc54fab35aebb9'),
    ]),
    ('1.99.1', 'unwind'): policies(48, 190, 6, [
        ('key128', '7d09ac3b2b0ed92409dddf14508e8b462cf7f23d67522914b2c2e98d8c518aca', '65b82885ed0678ebb564b7ea3ee533040f3a079177f14b95b34484efd2a1683b'),
        ('key192', 'a236c67a0708d56194f9f507ac43eabf5bb8a617e5047721d0501ca12e56fff6', '52bcca3da6f8243e14860e3fdcd74a43adee3af6be00a8904b502ef6c7819976'),
        ('key256', 'c4cdf67ba3b681d2057d9ac6a3c660d893e083f8d02191b896e6f87aec9df1ee', '42da3d972100b8b9e63e674976f06631d5f24104e4eea6fcde4eb006275ab8cf'),
        ('cached128', '1272d5edef78b6ad47f9d0e18e298459c853321914e00ad2f8cfe44624e352ec', '57920f844e750ea69fa39934e43f9c53f8d877cdad83fc488d7899f6572ad549'),
        ('cached192', '4a8bfb6083e0de6480152344b9a1d1685165e6f931cd3eb4c6a00b1038dd7fa7', '4cf91e0c9f3812deb16375fdc2a4f950213521d514c85bc9b2c9e2c080370e9a'),
        ('cached256', '14728385c3830a2fb29a4a68017833d83d8865e445129cccb371cd1ff5af9593', 'b63182a5a0a9f8e928cb9a43a75260bec3fb532ab0a3394cf8a3ef58e9f66926'),
    ]),
}


def check(lines, raw, sizes, symbol, start, image, targets, role, compiler, panic):
    require((compiler, panic) in POLICY and role in WIDTHS, 'unreviewed cleanup configuration')
    require(set(targets) == ({'zeroize', 'resume'} if panic == 'unwind' else {'zeroize'}),
            'cleanup call target population changed')
    actual, _ = image_review.observe(lines, raw, sizes, symbol, start, image, targets, callback(compiler, panic))
    require(actual == POLICY[compiler, panic][role], 'reviewed cleanup changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, raw, sizes, symbol, start, image, targets, role, compiler, panic):
    check(lines, raw, sizes, symbol, start, image, targets, role, compiler, panic)
    reason = 'reviewed cleanup changed'
    clears = [i for i, line in enumerate(lines) if line.endswith('<' + targets['zeroize'][0] + '>')]
    require(len(clears) == (4 if panic == 'unwind' else 2), 'cleanup call population changed')
    branch = next(i for i, line in enumerate(lines) if line.startswith('je '))
    callback_index = lines.index(callback(compiler, panic))
    source = next(i for i, line in enumerate(lines) if line.startswith('movq %r8,'))
    width = next(i for i, line in enumerate(lines) if line.startswith(f'movq ${WIDTHS[role]},'))
    changes = [(0, 'movb (%rdi,%rax), %al', reason),
               (branch, re.sub(r'0x[0-9a-f]+', '0x0', lines[branch], count=1), 'branch destination mismatch'),
               (clears[0], re.sub(r'0x[0-9a-f]+', '0x0', lines[clears[0]], count=1), 'call destination mismatch'),
               (source, lines[source].replace('%r8,', '%rdx,'), reason),
               (callback_index, 'callq *%rax', 'unsupported call'),
               (clears[0] - 1, 'xorl %esi, %esi', reason),
               (width, lines[width].replace(f'${WIDTHS[role]},', '$0,'), reason)]
    changes.extend((i, 'nop', reason) for i in clears)
    cases = []
    for index, replacement, expected in changes:
        changed = list(lines)
        changed[index] = replacement
        cases.append((changed, raw, image, expected))
    code, executable = bytearray(raw), bytearray(image)
    offset = image_review.file_offset(image_review.segments(image), start, len(raw), 5)
    code[0] ^= 1
    executable[offset] ^= 1
    cases.append((lines, bytes(code), bytes(executable), reason))
    for text, code, executable, expected in cases:
        try:
            check(text, code, sizes, symbol, start, executable, targets, role, compiler, panic)
        except ValueError as error:
            require(expected in str(error), 'cleanup mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES linked cleanup mutation accepted')
    return len(cases)
