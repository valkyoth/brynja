"""Bounded ARM constructor review with integrated hardware expansion.

Policies follow explicit whole-body inspection, not automatic hash refresh.
Static/hosted and compiler/panic variants are distinct. Native qualification
and operation callers are outside this ELF/emulated-construction slice.
"""
import hashlib
import importlib.util
from pathlib import Path
import re


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


cleanup = module('aes_accelerated_linked_arm_cleanup')
portable = module('aes_aarch64_linked')
expansion = module('aes_accelerated_linked_expansion')
kernels, require, TARGET = cleanup.kernels, cleanup.require, cleanup.TARGET


def policies(count, branches, cached, hashes, calls=None):
    return {bits: dict(instructions=count + (i if cached else 0), branches=branches,
                      calls=calls if calls is not None else 6 if cached else 2,
                      constants=0, tail_calls=0 if cached else 1,
                      text_sha256=text, encoding_sha256=encoding)
            for i, (bits, (text, encoding)) in enumerate(zip((128, 192, 256), hashes))}


# Whole constructor bodies: clear before admission, bind authority/generation,
# copy exact extent, and (cached) zero/expand/clear temporary schedule and handle
# the failure/quarantine path. No exception-table-dispatch claim.
RAW_STATIC_ABORT = policies(45, 5, False, [
    ('7ae3a1c2f25717319f61d81923079ba2345cea6a1cb54e8dc79a14a373cebf0a', '49f62c015ed546d0500ce2aa1158bf8efeada066d599d19aee94f4a602ac502a'),
    ('3107b67d0dd0c9de4f30fd4b8ee854f85069aeadf620b5df4ee3ab457ec26ca0', 'acd42f7fe6a30b656b804a27099ec5b6a9fe8aa86bbd7ecc467f880255e46c3d'),
    ('712ce6bf4a75029ee5e4939f57bc2038d99b2cb9f47a4e0c64c3f481d6ecde6f', '3b587672bcbb3a61d445d8d2d00503d22287ce968dc78a831075b0767b818ff9'),
])
RAW_STATIC = policies(45, 5, False, [
    ('1b38cb39ca0a58ecde0c283897fc923199b6ad55561704c4b87d63ca2d0a699d', '5045591825c953b11635d4af40e27c8bd8c1be095dac0f4820607ca822cd1894'),
    ('fcc472b7986ea899c01d79586ae2704a1ecc46a905389aa1ccbdc40fbd4be77d', 'b2c02be84cef178d8717585a07f5e9fb27e4f0c6dc62019e0f5fcb77e0139f20'),
    ('f29358648b4389c737c004a60bf57ed856a04059a94d9c0fe2d0421a42f0b7c4', 'fd1f013586a4947bb98279398f64d9f337ac8b1754320696f3f53b8a3c47eeb5'),
])
RAW_HOSTED_ABORT = policies(50, 7, False, [
    ('8825eed8265febe47e530949c5427a62f8fbb01ddd4c4aec9b6e7b511f3b3291', 'a423a71cbf0e8f3a17d8eb2cd515220d4daf7e6dd334efd50c57b0507fc39d5f'),
    ('d217662387759c7a7a59d221129ed27e040cbb3f7388821697df39a0948a08e8', '73d4fea5afcd978c9d0b83357fb5b6f7f3e58ec8b1741cc8970003da0f2f1afe'),
    ('924b29a02a3fbf71e443fccd97f4a63dfd954e3492065db2a4f0af62f43f7690', '0411d2a0dc40a9cb412ae36bc7b1697ed0424afcda815023f9392b8e6acdad83'),
])
RAW_HOSTED_UNWIND = policies(50, 7, False, [
    ('69d21d38ef740cf7f01e73d69a0f5de4c1910e657e445d874ae3694f88130e3b', '52538ba2346de9e025da2ba160e284308f7e4f52be19b84ed17e264bb964dc82'),
    ('a3488034b5e3ee9b5bc3e448d4c47c693b72f1b69b8950ed25805ef1463944da', '61d282b5f4558ad4e19f9f485ab7183588ef7b3730183c6e5dc6fa42f44d4bd6'),
    ('f0a1babd8e8cc7106e886a68ac5eee0a3b45f7407506d57e34adfee530d73875', 'e2258293c24b847ec91eaaba79871523fdcc18742fd94919fb04689faa1b2017'),
])
RAW_HOSTED_CURRENT = policies(47, 6, False, [
    ('9d29379b8ef6311b428a9519a98596ef6adee7d555d162a77ecb00992709d010', '617ae538a8ff32348074601f8ea7c8e12a84d0e398da8684c7f93aab99959084'),
    ('d3e94d8b72ec7a80c1b0df33d038f2c83eaeaa89fdba2828471f6efffb6f2179', 'ccb27cf024b48a3c7c9984748c8c5b70329e3c1d1ba2cf4fe799448128c477b2'),
    ('6fe55dc0a071eed5b3b2d6b11a79d67a2eec148ab8c56827752276eb19e3efb7', '8108481d36bf9117826802082105fbc69b4612b0b35e2389d4ad57202ef9ae62'),
])
CACHED_STATIC = policies(95, 14, True, [
    ('406e439bf9c52336a47b3634fda7af929f17bf02f70b285f344f915a130ca281', 'd4cc14419e00f7e641a755b922436eaf7eee661c3dbe05504fe59b2937d01059'),
    ('33d80f7a2f78668dd44d43e3259bd578fbc098710807e5585813fba0e6948d62', '61237063c9dd2c8c927622cb95886519c899290769d5f939c793dd95fdb7ae9e'),
    ('157a6764cc0e69dfde895b0a6229ff802c22f55ef3130b8bfec3e3114b488956', '081c19e547d0f51d46790d7005153f21c9ce3287a0b808f95955fa405da2c173'),
])
CACHED_STATIC_UNWIND = policies(129, 17, True, [
    ('f433212f3b428145b8061291c5d2b89ee2871fe4ed198c7be730eecb32987460', 'ce0c479d8ea99954a6d69fec8fa45f1391739f19b4a1ed9dc6ac203c1cf5bd15'),
    ('b156693b17dc4e7ab5659488d562b7b4269ceeb64c8fc7692607d11e0a2bb6ed', '2c85d92d14f368c23cfa9df64508d83f8594830c3e37a1a75916bcfe82f46f24'),
    ('e2d4ab8586aae88a8b794af7dd4808d598751d2f000cb7a60a6b1f369e21ef3b', 'e09205a3ab1faf4fc5245b45140559f643df88c090beacc2b6efe49c2700c085'),
], calls=12)
CACHED_HOSTED_ABORT = policies(105, 18, True, [
    ('2e3b7e5c63ced5f756ecbcd694db99de728fecc72355a133dbdd5a859a3ee9e9', '028589f41cc9092b0a7203a019e657fc3d3634c9e0e03152d146f3fa29064053'),
    ('9f52eddecfda2d0f561c22dcc28f71f1538152f78b2710705dd10ae8e1228c31', 'f7b1a24b51acf6a1c81fea282538c51f3c249a072d3864d0f937eab8519470ef'),
    ('e5a0b1d3e0b8834d9abdd254b2b02c277c9af7a1818f75979ce4b6a835d4f978', '420e0f4a8f7c97979ecc0c3272d02ea4e6c73f0eb012fd49289ec2aba7d3a173'),
])
CACHED_HOSTED_UNWIND = policies(139, 21, True, [
    ('11cf50afbcb06cfae2d1b56ddf329fd6efe94b7e133fe816457571ace2c94c5f', 'd412526d02dfeca1931a6676f0e3a1ceb897d058d241d484e2b30065cf55d756'),
    ('2ea94b85d6402e248cce403e50e32aebbf3122051ff7ab1c9c847ba850b9597a', 'fa927b274629a9082320bc186f19c9e868bddd9d6d04c6b9dd6892b150f7c963'),
    ('cf9437a52b805d981f9a02ee4b7d26a0b199cd4c2b669b1bf034cba5d76ccea8', '7490f156604b1f7cad3926cadd3f2c44b5b24f97cf0e4633c8e863fae8adccbe'),
], calls=12)
CACHED_HOSTED_CURRENT = policies(99, 16, True, [
    ('6ff40f42ac9f5e2e332c0213a09e34b45936d02c82068ca58da57198b735f5ef', '44dc62f408e445f326c57765ca43c0545cec0327656177f7f6cc8cd3260859e5'),
    ('32751fe68c15fabf3ca3dcfbc8613da65f22924570e0a3aed1e61c03a399787b', '8794ab38db9e0f2cc602b6bc93ff2b435099a873a94437e3dade41a9a8255626'),
    ('2690704efddf5879c4325bbd4a0eb1e077beb886f143355b5b9750a0c38007aa', '76e1ce67b6f6005948dd9331c97aed39a49ab0b05f31f300670147cc6d22aa44'),
])
CACHED = {
    ('1.90.0', 'abort', 'static'): CACHED_STATIC,
    ('1.90.0', 'unwind', 'static'): CACHED_STATIC_UNWIND,
    ('1.90.0', 'abort', 'hosted'): CACHED_HOSTED_ABORT,
    ('1.90.0', 'unwind', 'hosted'): CACHED_HOSTED_UNWIND,
    ('1.99.1', 'abort', 'static'): CACHED_STATIC,
    ('1.99.1', 'unwind', 'static'): CACHED_STATIC,
    ('1.99.1', 'abort', 'hosted'): CACHED_HOSTED_CURRENT,
    ('1.99.1', 'unwind', 'hosted'): CACHED_HOSTED_CURRENT,
}
COPY = dict(instructions=21, branches=4, calls=0, constants=0,
            text_sha256='a6317413c158ed680a11e50725200e4293d0aab7c03de3b1dd8191177c2be77e',
            encoding_sha256='a3cc162cd5727cb6f36dfb8cd0e3842007e0d81c9b0e5fd0a1b68e6974d1d460')


def policy(role, bits, compiler, panic, admission):
    require((compiler, panic, admission) in CACHED
            and role in ('raw', 'cached') and bits in (128, 192, 256), 'unreviewed ARM constructor configuration')
    if role == 'cached':
        return CACHED[compiler, panic, admission][bits]
    if admission == 'static':
        return (RAW_STATIC_ABORT if (compiler, panic) == ('1.90.0', 'abort') else RAW_STATIC)[bits]
    return (RAW_HOSTED_CURRENT if compiler == '1.99.1' else
            RAW_HOSTED_ABORT if panic == 'abort' else RAW_HOSTED_UNWIND)[bits]


def decode(assembly, row):
    lines, raw, sizes = kernels.decode(assembly, row, TARGET)
    require(sizes == [4] * len(lines), 'ARM constructor instruction partition changed')
    # Match the existing portable decoder's integer spelling only; never erase
    # instruction operands or branch/register identities.
    return [re.sub(r'#(-?)0x([0-9a-f]+)', lambda m: '#' + m[1] + str(int(m[2], 16)), line)
            for line in lines], raw


def candidates(table, assembly, image):
    selected = {}
    for line in table.splitlines():
        constructor = '30brynja_aes_accelerated_fixture9lifecycle' in line and 'new_' in line
        copy = 'secret_memory_transfer10copy_bytes' in line
        if not (constructor or copy):
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized ARM constructor dependency row')
        address, size, name = match.groups()
        row = name, int(address, 16), int(size, 16)
        if constructor:
            suffix = r'6aes(128|192|256)(7new_key|10new_cached)'
            match = (re.fullmatch(r'_ZN30brynja_aes_accelerated_fixture9lifecycle' + suffix + r'17h[0-9a-f]{16}E', name)
                     or re.fullmatch(r'_RNvNtNtC\w+_30brynja_aes_accelerated_fixture9lifecycle' + suffix, name))
            require(match is not None, 'unrecognized ARM constructor symbol')
            role = ('raw' if match[2] == '7new_key' else 'cached') + match[1]
        elif copy:
            require(re.fullmatch(r'(?:_ZN11brynja_core22secret_memory_transfer10copy_bytes17h[0-9a-f]{16}E|'
                                 r'_RNvNtC\w+_11brynja_core22secret_memory_transfer10copy_bytes)', name),
                    'unrecognized ARM copy symbol')
            role = 'copy'
        require(role not in selected, 'duplicate ARM constructor dependency')
        selected[role] = row
    for row in expansion.select(table, TARGET):
        result = expansion.check(*kernels.decode(assembly, row, TARGET), row, image, TARGET)
        role = 'expand' + str(result['bits'])
        require(role not in selected, 'duplicate ARM expansion width')
        selected[role] = row
    expected = {'copy', *(kind + str(bits) for kind in ('raw', 'cached', 'expand') for bits in (128, 192, 256))}
    require(set(selected) == expected, 'ARM constructor dependency population changed')
    cleanup.disjoint(selected.values())
    return selected


def check(lines, raw, row, image, targets, role, bits, compiler, panic, admission):
    expected = policy(role, bits, compiler, panic, admission)
    edges = {'zeroize', 'copy'}
    if role == 'cached':
        edges.add('expand')
        if (compiler, panic) == ('1.90.0', 'unwind'):
            edges.add('resume')
    require(set(targets) == edges,
            'ARM constructor call population changed')
    cleanup.disjoint([row, *targets.values()])
    actual, _, _ = portable.observe(lines, raw, row, image, targets, tail_calls=('zeroize',))
    require(actual == expected, 'ARM constructor stream changed; explicit re-review required')
    return {'role': role, 'bits': bits, **actual}


def check_copy(lines, raw, row, image):
    actual, _, _ = portable.observe(lines, raw, row, image, {})
    require(actual == COPY, 'ARM copy stream changed; explicit re-review required')
    return actual


def mutations(checker, lines, raw, row, image, *args):
    checker(lines, raw, row, image, *args)
    pos = kernels.mapped(image, TARGET, row[1], row[2])
    rejected = 0
    for index in range(len(lines) + len(raw)):
        text, data, binary = list(lines), raw, image
        if index < len(lines):
            text[index] = 'unreviewed-instruction'
        else:
            i = index - len(lines)
            data = raw[:i] + bytes([raw[i] ^ 1]) + raw[i + 1:]
            binary = image[:pos] + data + image[pos + len(raw):]
        try:
            checker(text, data, row, binary, *args)
        except ValueError as error:
            require(any(reason in str(error) for reason in ('stream changed', 'encoding mismatch',
                    'decoded/encoded destination mismatch')), 'constructor mutation rejected for unrelated reason: ' + str(error))
            rejected += 1
        else:
            raise ValueError('ARM constructor/copy mutation accepted')
    return rejected


# Pinned runtime boundary bytes, not semantic qualification of libunwind.
# Relocations changed with hardware expansion; the runtime remains trusted.
RESUME = {'static': 'af22a706435880ce0a8fb238496ea5a3097534a551d0e130a4943452f79c66f6',
          'hosted': '004cc2afe1c9443f352701f1f3fcfc37866422d738ae196f45d324aaacb7d45b'}


def resume_target(table, image, admission):
    require(admission in RESUME, 'unreviewed ARM runtime configuration')
    rows = [line for line in table.splitlines() if '_Unwind_Resume' in line]
    require(len(rows) == 1, 'missing/ambiguous ARM runtime boundary')
    match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) T _Unwind_Resume', rows[0])
    require(match is not None, 'unrecognized ARM runtime boundary')
    row = '_Unwind_Resume', int(match[1], 16), int(match[2], 16)
    require(row[1] % 4 == 0 and row[2] == 184, 'ARM runtime extent changed')
    pos = kernels.mapped(image, TARGET, row[1], row[2])
    require(hashlib.sha256(image[pos:pos + row[2]]).hexdigest() == RESUME[admission],
            'ARM runtime image changed; explicit re-review required')
    return row


def resume_mutations(table, image, admission):
    row = resume_target(table, image, admission)
    pos = kernels.mapped(image, TARGET, row[1], row[2])
    for i in range(row[2]):
        changed = image[:pos+i] + bytes([image[pos+i] ^ 1]) + image[pos+i+1:]
        try:
            resume_target(table, changed, admission)
        except ValueError as error:
            require('runtime image changed' in str(error), 'unrelated runtime mutation rejection')
        else:
            raise ValueError('ARM runtime mutation accepted')
    return row[2]


def inspect(table, assembly, image, compiler, panic, admission):
    policy('raw', 128, compiler, panic, admission)
    dependency = cleanup.inspect(table, assembly, image, compiler, panic, admission)
    selected = candidates(table, assembly, image)
    clearing = cleanup.candidates(table)
    runtime, runtime_controls = {}, 0
    if (compiler, panic) == ('1.90.0', 'unwind'):
        runtime['resume'] = resume_target(table, image, admission)
        runtime_controls = resume_mutations(table, image, admission)
    cleanup.disjoint([*selected.values(), *clearing.values(), *kernels.select(table, TARGET), *runtime.values()])
    helper_report = expansion.inspect(table, assembly, image, TARGET)
    row = selected['copy']
    args = (*decode(assembly, row), row, image)
    copy_report = check_copy(*args)
    rejected = mutations(check_copy, *args)
    constructors = []
    for kind in ('raw', 'cached'):
        for bits in (128, 192, 256):
            row = selected[kind + str(bits)]
            targets = {'copy': selected['copy'], 'zeroize': clearing['zeroize']}
            if kind == 'cached':
                targets['expand'] = selected['expand' + str(bits)]
                targets.update(runtime)
            args = (*decode(assembly, row), row, image, targets, kind, bits, compiler, panic, admission)
            constructors.append(check(*args))
            rejected += mutations(check, *args)
    expected = sum(policy(k, b, compiler, panic, admission)['instructions'] * 5
                   for k in ('raw', 'cached') for b in (128, 192, 256)) + 105
    require(rejected == expected, 'ARM constructor/copy mutation population changed')
    return {'constructors': constructors, 'copy': copy_report, 'expansion': helper_report,
            'rejected_constructor_copy_mutations': rejected,
            'rejected_expansion_mutations': helper_report['rejected_mutations'],
            'runtime_boundary': runtime, 'rejected_runtime_mutations': runtime_controls,
            'cleanup_review': dependency,
            'scope': 'six AArch64 package-external constructors, copy, hardware expansion and post-admission, '
                     'clear/destruction and round kernels; not operation callers, native qualification, '
                     'every fixture call site, arbitrary inlining, exception-table dispatch, unwinder qualification or spill erasure'}
