"""Narrow emitted owner/field cleanup checks; reject unmodeled MIR changes."""
from collections import Counter
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cryptography"))
import mir_cleanup_flow as flow


def require(value, label):
    if not value:
        raise ValueError("ParallelHash execution cleanup: " + label)


def body(mir, file, owner, method):
    return flow.exact_function(mir, ("crates/brynja-hash-parallel/src/execution/" + file + ":",
                                     "::" + method + "(", "_1: &mut " + owner))


def linear_fields(function, expected):
    """Bind each sanitizer call to one exact receiver field on a straight path.

    This is deliberately not a general Rust/MIR verifier. Cleanup methods have
    no branches, writes or callbacks. Any new shape must be reviewed explicitly.
    LLVM separately checks the emitted widths and straight-line call sites.
    This does not prove that an external callee can never unwind; the existing
    shared clearing/backend contracts remain part of the assurance closure.
    """
    blocks = flow.basic_blocks(function)
    current, seen, aliases, observed = "bb0", set(), {"_1": "self"}, []
    while current not in seen:
        seen.add(current)
        block = blocks[current]
        for line in block.splitlines():
            line = line.strip()
            if not line or line == "}" or line.startswith(("StorageLive(", "StorageDead(")):
                continue
            if line == "return;":
                require(observed == expected and seen == set(blocks), "exact mandatory cleanup fields")
                return
            if " -> [" in line:
                continue
            field = re.fullmatch(r"(_\d+) = (?:&mut|(?:no_retag )?copy) \(\(\*_1\)\.(\d+): .+\);", line)
            cast = re.fullmatch(r"(_\d+) = copy (_\d+) as &mut \[u8\] \(PointerCoercion\(Unsize, Implicit\)\);", line)
            if field:
                aliases[field[1]] = field[2]
            elif cast and cast[2] in aliases:
                aliases[cast[1]] = aliases[cast[2]]
            else:
                raise ValueError("unreviewed cleanup statement: " + line)
        call = flow.call_definition(block)
        require(call is not None, "straight cleanup call")
        destination, target, argument, successor, _ = call
        arg = re.fullmatch(r"(?:move|copy) (_\d+)", argument)
        require(arg and arg[1] in aliases, "cleanup argument field provenance")
        observed.append((target, aliases[arg[1]]))
        aliases.pop(destination, None)
        require(successor in blocks, "cleanup returns to a known block")
        current = successor
    raise ValueError("cyclic cleanup path")


def emitted(ll, pattern, widths, dynamic=0):
    functions = re.findall(r"^define [\s\S]*?^}", ll, re.M)
    selected = [fn for fn in functions if re.search(pattern, fn.splitlines()[0])]
    require(len(selected) == 1, "unique emitted cleanup definition")
    fn = selected[0]
    require("invoke " not in fn and " br " not in fn, "straight-line emitted cleanup")
    calls = [line for line in fn.splitlines() if not line.lstrip().startswith(";")
             and "call " in line and "clear_owned_region" in line]
    sizes = [int(m[1]) for line in calls if (m := re.search(r"i(?:32|64)\s+(?:noundef\s+)?(\d+)\)", line))]
    require(Counter(sizes) == Counter(widths) and len(calls) == len(widths) + dynamic,
            "exact emitted cleanup widths")


def check(row):
    mir = row["mir"]
    collector = "Collector::<'_, '_, '_>::cancel("
    stream = "Stream::<'_, '_>::cancel("
    state = "execution::backend::State::<'_>::wipe("
    clear = "clear_owned_region("
    for file, owner, method, calls in (
        ("collector.rs", "Collector<", "cancel", [(state, "1"), *[(clear, str(i)) for i in range(2, 6)]]),
        ("stream.rs", "Stream<", "cancel", [(collector, "0"), *[(clear, str(i)) for i in range(1, 4)]]),
        ("collector.rs", "Collector<", "drop", [(collector, "self")]),
        ("stream.rs", "Stream<", "drop", [(stream, "self")]),
        ("collector.rs", "collector::Reader<", "drop", [(collector, "0")]),
        ("stream_output.rs", "StreamReader<", "drop", [(stream, "0")]),
        ("backend.rs", "execution::backend::State<", "drop", [(state, "self")]),
        ("encoding.rs", "Encoded)", "drop", [(clear, "0"), (clear, "1")]),
        ("mod.rs", "Clear<", "drop", [(clear, "0")]),
    ):
        linear_fields(body(mir, file, owner, method), calls)
    wipe = body(mir, "backend.rs", "execution::backend::State<", "wipe")
    for token in ("HardenedCshake128::wipe_in_place(", "HardenedCshake256::wipe_in_place(",
                  "Cshake128::", "Cshake256::"):
        require(token in wipe, "every hardened variant cleared")
    emitted(row["ll"], r"execution.*collector.*Collector.*cancel", [16, 16, 16, 1])
    emitted(row["ll"], r"execution.*stream.*Stream.*cancel", [16, 16], dynamic=1)
    emitted(row["ll"], r"execution.*encoding.*Encoded.*drop", [17, 1])
    for pattern in (r"execution.*collector.*Collector.*cancel", r"execution.*stream.*Stream.*cancel"):
        require(re.search(pattern, row["s"]), "assembly destruction boundary")


def check_storage(row):
    """Bind std destruction to its independently tested slot-clearing loop.

    This is compiler inspection, not a formal proof of Vec iteration. The
    compiled destructive mutation and runtime all-byte tests cover that loop.
    """
    headers = ("crates/brynja-hash-parallel-std/src/execution/worker.rs:",
               "::drop(", "_1: &mut Storage)")
    function = flow.exact_function(row["mir"], headers)
    linear_fields(function, [("Storage::clear(", "self")])
    functions = re.findall(r"^define [\s\S]*?^}", row["ll"], re.M)
    selected = [fn for fn in functions if re.search(r"execution.*worker.*Storage.*clear", fn.splitlines()[0])]
    require(len(selected) == 1, "unique std storage clearing definition")
    code = "\n".join(line for line in selected[0].splitlines() if not line.lstrip().startswith(";"))
    calls = [line for line in code.splitlines() if "call " in line and "clear_owned_region" in line]
    require(len(calls) == 1 and re.search(r"i64 (?:noundef )?64\)", calls[0]),
            "complete 64-byte slot clearing call")
    require(re.search(r"phi ptr", code) and re.search(r"getelementptr[^\n]+i64 64", code),
            "std storage iteration survives optimization")
    require(re.search(r"execution.*worker.*Storage.*clear", row["s"]),
            "std storage assembly clearing definition")
