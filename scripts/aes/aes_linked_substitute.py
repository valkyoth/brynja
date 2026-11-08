"""Exact reviewed substitution streams; calls must bind to the reviewed inverse.

The runner also checks the inverse body against its separate policy. Merely
supplying a symbol address to this module does not qualify the callee.
"""
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('substitute_linked_image', Path(__file__).with_name('aes_linked_mix.py'))
image_review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image_review)
require = image_review.require

POLICY = {
    '1.90.0': {'instructions': 456, 'symbol_bytes': 1308, 'constant_loads': 0, 'calls': 32,
               'text_sha256': 'b6ec27162477d07ab81669df12ed7705cb0320ddd90db25f90b327b784fe0670',
               'encoding_sha256': 'f57549d31cfcb22849a0df8f996ae84c69bda3f2f0d37b680022d98f4d70804f'},
    '1.99.1': {'instructions': 577, 'symbol_bytes': 2059, 'constant_loads': 1, 'calls': 32,
               'text_sha256': 'bdea25d1279c3b94636f07f83b2cc5a33e88116b0af6075462d7fc69dfa9aedf',
               'encoding_sha256': '7e69a4e465293457814681dffb3689eece5723cf7d617718371b636f3d0947b7'},
}


def check(lines, raw, sizes, symbol, start, image, inverse, compiler):
    require(compiler in POLICY, 'unreviewed substitution compiler')
    actual, _ = image_review.observe(lines, raw, sizes, symbol, start, image, {'inverse': inverse})
    require(actual == POLICY[compiler], 'reviewed substitution changed; explicit re-review required')
    return {'role': 'substitute', **actual}


def mutations(lines, raw, sizes, symbol, start, image, inverse, compiler):
    call = next(i for i, line in enumerate(lines) if line.startswith('callq '))
    branch = next(i for i, line in enumerate(lines) if line.startswith('je '))
    changed = list(lines)
    changed[0] = 'movb (%rdi,%rax), %al'
    bad_target = list(lines)
    bad_target[call] = re.sub(r'0x[0-9a-f]+', '0x0', bad_target[call], count=1)
    bad_symbol = list(lines)
    bad_symbol[call] = bad_symbol[call].replace('<' + inverse[0] + '>', '<other>')
    bad_branch = list(lines)
    bad_branch[branch] = re.sub(r'0x[0-9a-f]+', '0x0', bad_branch[branch], count=1)
    pos = image_review.file_offset(image_review.segments(image), start, len(raw), 5)
    call_offset = sum(sizes[:call])
    redirected, redirected_image = bytearray(raw), bytearray(image)
    redirected[call_offset + 1] ^= 1
    redirected_image[pos:pos + len(raw)] = redirected
    encoded, encoded_image = bytearray(raw), bytearray(image)
    encoded[0] ^= 1
    encoded_image[pos:pos + len(raw)] = encoded
    cases = [(changed, raw, image, 'reviewed substitution changed'),
             (bad_target, raw, image, 'call destination mismatch'),
             (bad_symbol, raw, image, 'call destination mismatch'),
             (bad_branch, raw, image, 'branch destination mismatch'),
             (lines, bytes(redirected), bytes(redirected_image), 'call destination mismatch'),
             (lines, bytes(encoded), bytes(encoded_image), 'reviewed substitution changed')]
    for text, code, executable, reason in cases:
        try:
            check(text, code, sizes, symbol, start, executable, inverse, compiler)
        except ValueError as error:
            require(reason in str(error), 'mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES linked substitution mutation accepted')
    return len(cases)
