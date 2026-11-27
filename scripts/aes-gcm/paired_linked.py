"""Bounded inspection of linked x86-64 archive consumers, not a timing proof."""
from collections import Counter
import hashlib
import re
import subprocess

HEADER = re.compile(r"^([0-9a-f]+) <(.+)>:$")
INSN = re.compile(r"^\s*[0-9a-f]+:\s+(\S+)(?:\s+(.*))?$")
REL = re.compile(r"^([0-9a-f]+)\s+R_X86_64_RELATIVE\s+\*ABS\*\+0x([0-9a-f]+)$")
GOT = re.compile(r"^\*[-+0-9a-fx]+\(%rip\)\s+# 0x([0-9a-f]+)(?:\s|$)")
DIRECT = re.compile(r"^0x([0-9a-f]+)(?:\s|$)")


class Image:
    def __init__(self, assembly, relocations):
        self.names, self.bodies, self.slots = {}, {}, {}
        if not any(line.endswith("\tfile format elf64-x86-64") for line in assembly.splitlines()):
            raise ValueError("not an x86-64 ELF disassembly")
        for line in relocations.splitlines():
            if m := REL.fullmatch(line):
                slot, function = (int(n, 16) for n in m.groups())
                if slot in self.slots:
                    raise ValueError("ambiguous relocation")
                self.slots[slot] = function
        current = None
        for line in assembly.splitlines():
            if m := HEADER.fullmatch(line):
                current = int(m[1], 16)
                if current in self.names:
                    raise ValueError("ambiguous function address")
                label = re.sub(r" (?:\(\.llvm\.\d+\))$", "", m[2])
                for old, new in (("$LT$", "<"), ("$GT$", ">"), ("$u20$", " "), ("..", "::")):
                    label = label.replace(old, new)
                self.names[current] = re.sub(r"::h[0-9a-f]{16}$", "", label).replace(">::", "::").lstrip("<")
                self.bodies[current] = []
            elif current is not None and (m := INSN.fullmatch(line)):
                self.bodies[current].append((m[1], m[2] or ""))

    def calls(self, addr):
        # Only concrete local edges, not text in the disassembler's comments.
        for op, operand in self.bodies[addr]:
            if op not in ("callq", "jmp", "jmpq"):
                continue
            if m := DIRECT.match(operand):
                dest = int(m[1], 16)
            elif m := GOT.match(operand):
                dest = self.slots.get(int(m[1], 16))
            else:
                continue
            if dest in self.names and dest != addr:
                yield dest

    def base(self, addr):
        return self.names[addr].split("::<", 1)[0]

    def children(self, addr, name):
        return {a for a in self.calls(addr) if self.base(a) == name}


PORT = "brynja_aead_gcm::aes_gcm::portable::"
FRAME = "brynja_aead_gcm::aes_gcm::Frame::hash"
UPDATE = "brynja_universal_hash_ghash::ghash::Ghash::update"
PRODUCT = "brynja_crypto_cpu::ghash_pclmul::runtime::RuntimeProduct::product"
MULTIPLY = "brynja_crypto_cpu::ghash_pclmul::multiply"
TRANSFORM = "brynja_crypto_cpu::aes::x86::transform"
CORE = "brynja_core::secret_memory"
ACC, PRED = CORE + "::accumulate_secret_byte_difference", CORE + "::secret_difference_is_zero"
BYTE, MASK = CORE + "_difference::accumulate_byte", CORE + "_predicate::mask_is_zero"


def require(value, message):
    if not value:
        raise ValueError("paired linked screen: " + message)
    return value


def unique(image, name):
    matches = [a for a in image.names if image.base(a) == name]
    require(len(matches) == 1, "missing or ambiguous " + name)
    return matches[0]


def check_leaf(image, name, instructions):
    body = list(image.bodies[unique(image, name)])
    while body and body[-1][0] == "int3":
        body.pop()
    require(body == instructions, "changed comparison leaf: " + name)


def field_route(image, frame):
    require(any("AesPair" in image.names[a] and image.base(a).endswith("HashRoute::start")
                for a in image.calls(frame)), "missing paired hash start")
    require(image.children(frame, "brynja_universal_hash_ghash::ghash::Ghash::finish"), "missing hash finish")
    path = {frame}
    for stage in (UPDATE, PRODUCT, MULTIPLY):
        path = {target for a in path for target in image.children(a, stage)}
        require(path, "missing linked frame edge to " + stage)
    for a in path:
        body = image.bodies[a]
        require(sum(op == "pclmulqdq" for op, _ in body) == 4 and
                not any(op.startswith(("j", "call", "loop")) or op == "<unknown>" for op, _ in body),
                "changed field multiply body")


def aes_width(image, material):
    candidates = {a for a in image.calls(material)
                  if PORT + "paired::Aes" in image.names[a] and image.base(a).endswith("Forward::encrypt")}
    require(len(candidates) == 1, "material not bound to exactly one paired AES width")
    forward, = candidates
    width = require(re.search(r"paired::Aes(128|192|256)ExpandedKey", image.names[forward]),
                    "unknown paired width")[1]
    owner = "brynja_cipher_aes::aes::execution::Aes" + width + "ExpandedKey"
    public = image.children(forward, owner + "::encrypt_block")
    wrappers = {forward} | public
    for wrapper in public:
        secret = image.children(wrapper, owner + "::secret")
        if secret:
            # In the non-inlined SysV wrapper the fifth argument is inverse.
            # Only accept the observed straight-line thunk setting it to false.
            code = [(op, arg) for op, arg in image.bodies[wrapper] if op != "int3"]
            require(len(secret) == 1 and len(code) == 7
                    and code[:3] == [("pushq", "%rbx"), ("movq", "%rdi, %rbx"), ("xorl", "%r8d, %r8d")]
                    and code[3][0] == "callq"
                    and code[4:] == [("movq", "%rbx, %rax"), ("popq", "%rbx"), ("retq", "")],
                    "unrecognized encrypt direction thunk for " + width)
            wrappers.update(secret)
    sessions = {s for w in wrappers for s in image.children(w, "brynja_crypto_cpu::aes::Session::encrypt" + width)}
    leaves = {t for s in sessions for t in image.children(s, TRANSFORM)}
    require(len(leaves) == 1, "missing AES forward session/round path for " + width)
    leaf, = leaves
    mix = Counter(op for op, _ in image.bodies[leaf])
    require(mix["aesenc"] and mix["aesenclast"], "missing forward round instructions")
    return width, leaf


def compare_sites(image, addr, acc, pred):
    # Some LLVM builds keep the accumulator callee in a register for a
    # tag-byte loop. Count only loads from its actual relocated GOT slot
    # followed by calls through that register. This is not a CFG proof.
    # Only recognise preserved registers. Conservatively forget a cached
    # pointer on any other mention of that register (including subregisters).
    preserved = {f"%r{n}": re.compile(rf"%r{n}(?:b|w|d)?\b") for n in range(12, 16)}
    regs, count = set(), 0
    for op, operands in image.bodies[addr]:
        if op != "callq":
            regs = {r for r in regs if not preserved[r].search(operands.split("#")[0])}
        if op == "movq" and (m := re.fullmatch(r"[-+0-9a-fx]+\(%rip\), (%\w+)\s+# 0x([0-9a-f]+)(?: .*)?", operands)):
            if image.slots.get(int(m[2], 16)) == acc and m[1] in preserved:
                regs.add(m[1])
        if op != "callq":
            continue
        m = GOT.match(operands)
        d = DIRECT.match(operands)
        target = image.slots.get(int(m[1], 16)) if m else int(d[1], 16) if d else None
        if target == pred:
            return count
        if target == acc or operands.removeprefix("*") in regs:
            count += 1
    return 0


def review(image, version):
    require(not any("aes_gcm::interruptions::" in n for n in image.names.values()), "test hook symbol in consumer")
    material = [a for a in image.names if image.base(a) == PORT + "with_material"]
    frame = unique(image, FRAME)
    field_route(image, frame)
    acc, pred = unique(image, ACC), unique(image, PRED)
    require(image.children(acc, BYTE) and image.children(pred, MASK), "unlinked comparison leaves")
    check_leaf(image, BYTE, [("movzbl", "(%rsi), %eax"), ("xorb", "(%rdx), %al"),
                             ("orb", "%al, (%rdi)"), ("xorl", "%eax, %eax"), ("retq", "")])
    check_leaf(image, MASK, [("movzbl", "(%rdi), %r10d"), ("andl", "%esi, %r10d"),
                             ("sete", "%al"), ("movzbl", "%al, %eax"), ("xorl", "%r10d, %r10d"), ("retq", "")])
    widths, totals, sites = {}, Counter(), {w: [] for w in ("128", "192", "256")}
    callers = {w: {t for a in image.names if "paired::Aes" + w + "ExpandedKey" in image.names[a]
                   and image.base(a).endswith("Forward::operation") for t in image.calls(a)} for w in sites}
    for a in material:
        width, leaf = aes_width(image, a)
        require(a in callers[width], "material not bound to matching paired operation")
        totals[width] += 1
        require(widths.setdefault(width, leaf) == leaf, "inconsistent forward kernel")
        targets = set(image.calls(a))
        require(frame in targets or any(frame in image.calls(t) for t in image.children(a, PORT + "masked_tag")),
                "disconnected GHASH frame")
        if pred in targets:
            sites[width].append(compare_sites(image, a, acc, pred))
    expected = {"1.90.0": [1]*5, "1.100.0": list(range(12, 17))}.get(version)
    require(expected and len(set(widths.values())) == 3 and
            all(totals[w] == 10 and sorted(sites[w]) == expected for w in sites),
            "changed material/verification call-site coverage")
    return len(material)


def digest(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def load(path):
    def dump(*args):
        return subprocess.check_output(["llvm-objdump", *args, str(path)], text=True, timeout=60)
    return Image(dump("-d", "-C", "--no-show-raw-insn"), dump("-R"))
