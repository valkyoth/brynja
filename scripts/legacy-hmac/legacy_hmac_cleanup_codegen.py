"""Legacy Scratch population over the existing fail-closed LLVM path checker."""
import importlib.util
from pathlib import Path
import re

# Load the shared pure flow checker by exact repository path. Do not alter its
# modern-HMAC population or accept family-folder module shadowing.
PATH = Path(__file__).resolve().parents[1] / "hmac/hmac_cleanup_codegen.py"
SPEC = importlib.util.spec_from_file_location("legacy_scratch_flow", PATH)
flow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flow)
PROBES = {"scratch_1": 1, "scratch_20": 20, "scratch_64": 64,
          "scratch_unwind": 64, "scratch_mask": 64}
require = flow.require
CLEAR = flow.CLEAR


def functions(llvm):
    result = {}
    for match in re.finditer(r"^define [^\n]*@(\w+)\([^\n]*\{\n(.*?)^\}", llvm, re.M | re.S):
        name, body = match.groups()
        for probe in PROBES:
            if re.search(r"26brynja_legacy_hmac_cleanup" + str(len(probe)) + probe + r"(?:17h\w+E)?$", name):
                require(probe not in result, "duplicate legacy scratch probe " + probe)
                result[probe] = body
    require(set(result) == set(PROBES), "missing exact legacy scratch population")
    return result


def check(mir, llvm, assembly, panic):
    require(panic in ("abort", "unwind"), "unknown panic profile")
    require(re.search(r"fn scratch::.*::drop\(_1: &mut Scratch<N>\)", mir), "actual Scratch destructor MIR missing")
    require("clear_owned_region(" in mir, "MIR clearing call absent")
    for name, body in functions(llvm).items():
        flow.check_body(body, PROBES[name], panic)
        require(name in assembly, "assembly probe absent: " + name)
    require("clear_owned_region" in assembly, "assembly clear symbol absent")
