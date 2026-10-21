"""Small fail-closed LLVM integer evaluator; undefined bits never prove admission."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax

V, L, require = syntax.VALUE, common.LABEL, common.require
TOKEN = V + r'|-?\d+|true|false|null|undef|poison'


class Unknown:
    def __init__(self, value=0, known=0):
        self.value, self.known = value, known


def parts(value):
    return (value.value, value.known) if isinstance(value, Unknown) else (value, -1)


def integer(value, width):
    number, known = parts(value)
    mask = (1 << width) - 1
    require(known & mask == mask, 'undefined transaction result/condition bits')
    return number & mask


def evaluate(rhs, value, predecessor=None):
    phi = re.fullmatch(r'phi i\d+ (.*)', rhs)
    if phi:
        pairs = re.findall(r'\[ (' + TOKEN + r'), %' + L + r' \]', phi[1])
        require(phi[1] == ', '.join('[ ' + item + ', %' + label + ' ]' for item, label in pairs),
                'unparsed transaction phi')
        selected = [item for item, label in pairs if label == predecessor]
        require(len(selected) == 1, 'transaction phi predecessor')
        return value(selected[0])
    cast = re.fullmatch(r'(zext|trunc)(?: nuw)? i(\d+) (' + TOKEN + r') to i(\d+)', rhs)
    if cast:
        number, known = parts(value(cast[3]))
        source, dest = (1 << int(cast[2])) - 1, (1 << int(cast[4])) - 1
        number &= source
        known = (known & source | ~source) if cast[1] == 'zext' else known
        return number & dest if known & dest == dest else Unknown(number & dest, known | ~dest)
    compare = re.fullmatch(r'icmp(?: samesign)? (eq|ne|ult) (i\d+|ptr) (' + TOKEN + '), (' + TOKEN + ')', rhs)
    if compare:
        left, right = value(compare[3]), value(compare[4])
        if compare[2] != 'ptr':
            left, right = integer(left, int(compare[2][1:])), integer(right, int(compare[2][1:]))
        require(not isinstance(left, Unknown) and not isinstance(right, Unknown), 'unknown transaction comparison')
        return int(left == right if compare[1] == 'eq' else left != right if compare[1] == 'ne' else left < right)
    select = re.fullmatch(r'select i1 (' + TOKEN + r'), i\d+ (' + TOKEN + r'), i\d+ (' + TOKEN + ')', rhs)
    if select:
        return value(select[2] if integer(value(select[1]), 1) else select[3])
    extract = re.fullmatch(r'extractvalue \{ i8, i8 \} (' + V + '), ([01])', rhs)
    if extract:
        result = value(extract[1])
        require(isinstance(result, tuple) and len(result) == 2, 'transaction Result shape')
        return result[int(extract[2])]
    binary = re.fullmatch(r'(xor|or|and|shl)(?: nuw| nsw| disjoint)* i(\d+) (' + TOKEN + '), (' + TOKEN + ')', rhs)
    if binary:
        width = int(binary[2])
        mask = (1 << width) - 1
        left, lk = parts(value(binary[3]))
        right, rk = parts(value(binary[4]))
        if binary[1] == 'shl':
            require(rk & mask == mask and 0 <= right < width, 'unknown/oversized transaction shift')
            number, known = left << right, lk << right | ((1 << right) - 1)
        elif binary[1] == 'or':
            number, known = left | right, lk & rk | left & lk | right & rk
        elif binary[1] == 'and':
            number, known = left & right, lk & rk | ~left & lk | ~right & rk
        else:
            number, known = left ^ right, lk & rk
        return number & mask if known & mask == mask else Unknown(number & mask, known | ~mask)
    require(False, 'unreviewed transaction expression: ' + rhs)
