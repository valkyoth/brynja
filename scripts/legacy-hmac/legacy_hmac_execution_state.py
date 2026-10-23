"""Bounded metadata/copy model for the emitted borrowed SHA-1 owner ABI.

Only public discriminants are evaluated. Two logical Sha1Owner obligations
survive moves; copies are not claimed erased. Primitive Drop is a separately
reviewed, non-panicking cleanup contract, not re-proved here.
"""
import copy
import re

import legacy_hmac_engine_codegen as shared

require = shared.require
flow = shared.flow
shared.load("hmac_engine_update")
final = shared.load("hmac_engine_final")
SSA = r"%[-\w.]+"
VALUE = r"(?:%[-\w.]+|-?\d+|true|false)"
SIZE, ENGINE, NICHE = 912, 904, 897
OWNERS = {16: 0, 464: 1}


def method(symbol, operation):
    return bool(re.fullmatch(
        r"(?:_RNvMNtCs\w+_18brynja_legacy_hmac9executionNtB\w+_8Sha1Hmac|"
        r"_ZN18brynja_legacy_hmac9execution8Sha1Hmac)" + str(len(operation)) + operation
        + r"(?:17h[0-9a-f]+E)?", symbol))


def stream_update(symbol):
    return bool(re.fullmatch(
        r"(?:_RNvM(?:\w*_)?NtNtCs\w+_18brynja_legacy_sha118hardened_execution6streamNtB\w+_6Stream|"
        r"_ZN18brynja_legacy_sha118hardened_execution6stream6Stream)6update(?:17h[0-9a-f]+E)?", symbol))


def helper(symbol):
    return (("drop_glue" in symbol or "drop_in_place" in symbol)
            and "brynja_legacy_hmac" in symbol
            and ("Sha1Hmac" in symbol or "Sha1Adapter" in symbol))


class State:
    def __init__(self, niche):
        self.storage = {"state": (SIZE, {NICHE: niche}, dict(OWNERS) if niche != 2 else {})}
        self.capacity = {"state": SIZE}
        self.done = set()
        self.updates = self.observers = 0

    def clone(self):
        return copy.deepcopy(self)

    def region(self, pointer, width=1):
        require(isinstance(pointer, tuple) and len(pointer) == 2, "unknown owner pointer")
        root, offset = pointer
        require(root in self.storage and self.storage[root] is not None, "dead/uninitialized owner storage")
        size, metadata, owners = self.storage[root]
        require(0 <= offset <= size - width, "owner pointer out of range")
        return root, offset, metadata, owners

    def load(self, pointer):
        _, offset, metadata, _ = self.region(pointer)
        require(offset in metadata, "non-metadata owner load")
        return metadata[offset]

    def store(self, pointer, value):
        _, offset, metadata, _ = self.region(pointer)
        require(offset == NICHE and value == 2, "unexpected owner write")
        metadata[offset] = value

    def transfer(self, destination, source, width):
        root, offset, metadata, owners = self.region(source, width)
        require(offset == 0 and width in (SIZE, ENGINE), "partial owner copy")
        dest, start = destination
        require(start == 0 and dest != root and self.storage.get(dest) is None,
                "overwritten/aliased owner copy")
        require(dest in self.capacity and width <= self.capacity[dest], "copy exceeds allocation")
        require(not (set(owners.values()) & self.done), "copy after destruction")
        self.storage[dest] = (width, dict(metadata), dict(owners))

    def destroy(self, pointer):
        _, offset, metadata, owners = self.region(pointer, 433)
        require(metadata.get(NICHE) != 2 and offset in owners, "wrong/empty cleanup owner")
        token = owners[offset]
        require(token not in self.done, "duplicate owner cleanup")
        self.done.add(token)

    def end(self, pointer):
        root, offset, metadata, owners = self.region(pointer)
        require(offset == 0 and root != "state", "wrong lifetime end")
        require(metadata[NICHE] == 2 or set(owners.values()) <= self.done,
                "owner lifetime ends before destruction")
        self.storage[root] = None


def scalar(line, values, state, predecessor):
    """Reject unknown operations rather than treating conditions as arbitrary."""
    match = re.fullmatch(rf"({SSA}) = (.*)", line)
    if not match:
        return False
    name, expression = match.groups()

    def value(text):
        return operand(text, values)

    gep = re.fullmatch(rf"getelementptr inbounds(?: nuw)? i8, ptr ({SSA}), i64 (\d+)", expression)
    load = re.match(rf"load i8, ptr ({SSA}),", expression)
    compare = re.fullmatch(rf"icmp(?: samesign)? (eq|ne) i8 ({VALUE}), (-?\d+)", expression)
    pointer_compare = re.fullmatch(rf"icmp (eq|ne) ptr ({SSA}), null", expression)
    select = re.fullmatch(rf"select i1 ({VALUE}), i(?:1|8) ({VALUE}), i(?:1|8) ({VALUE})", expression)
    extract = re.fullmatch(rf"extractvalue \{{ i8, i8 \}} ({SSA}), ([01])", expression)
    trunc = re.fullmatch(rf"trunc(?: nuw)? i8 ({SSA}) to i1", expression)
    if gep:
        pointer = value(gep[1])
        state.region(pointer)
        result = pointer[0], pointer[1] + int(gep[2])
        state.region(result)
    elif load:
        result = state.load(value(load[1]))
    elif compare:
        source = value(compare[2])
        require(isinstance(source, int), "unknown comparison")
        result = int((source == int(compare[3])) == (compare[1] == "eq"))
    elif pointer_compare:
        state.region(value(pointer_compare[2]))
        result = int(pointer_compare[1] == "ne")
    elif select:
        condition = value(select[1])
        require(condition in (0, 1), "invalid select condition")
        result = value(select[2 if condition else 3])
    elif extract:
        source = value(extract[1])
        require(isinstance(source, tuple) and all(isinstance(v, int) for v in source), "unknown update result")
        result = source[int(extract[2])]
    elif trunc:
        result = value(trunc[1]) & 1
    elif expression.startswith("phi i8 "):
        choices = re.findall(rf"\[ ({VALUE}), %" + flow.LABEL + r" \]", expression)
        selected = [v for v, label in choices if label == predecessor]
        require(len(selected) == 1, "ambiguous result phi")
        result = value(selected[0])
    elif (expression == "landingpad { ptr, i32 }" or expression.startswith("phi { ptr, i32 } ")):
        return True  # Opaque exception payload, never used as owner provenance.
    else:
        return False
    values[name] = result
    return True


def operand(text, values):
    if text in ("true", "false"):
        return int(text == "true")
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    require(text in values, "undefined retained operand: " + text)
    return values[text]
