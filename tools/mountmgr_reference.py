"""Independently execute only ARM64 dispatch routing from original bytes/instructions."""

import argparse
import hashlib
import json
import re
import struct
from collections import Counter
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument(
    "--fixture",
    type=Path,
    default=Path(__file__).resolve().parents[1] / "tests/fixtures/mountmgr-arm64-bn6.json",
)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
fixture = json.loads(args.fixture.read_text())
base = 0x140000000
raw = args.binary.read_bytes()
if hashlib.sha256(raw).hexdigest() != fixture["file_sha256"]:
    raise ValueError("Expected the pinned mountmgr build")
pe = struct.unpack_from("<I", raw, 60)[0]
n = struct.unpack_from("<H", raw, pe + 6)[0]
opt = struct.unpack_from("<H", raw, pe + 20)[0]
sections = [struct.unpack_from("<IIII", raw, pe + 24 + opt + 40 * i + 8) for i in range(n)]


def read(address, size):
    rva = address - base
    for virtual_size, va, raw_size, offset in sections:
        if va <= rva and rva + size <= va + raw_size:
            return raw[offset + rva - va : offset + rva - va + size]
    raise ValueError(hex(address))


asm = {int(i["rva"], 16) + base: i["text"].strip() for i in fixture["reference_instructions"]}


def route(code, context):
    pc = base + (0x1899C if context == "host" else 0x18BEC)
    regs = {"19": code}
    flags = None
    path = []
    tables = []

    def val(s):
        s = s.strip()
        return int(s[1:], 0) if s.startswith("#") else regs[s[1:]]

    for _ in range(150):
        text = asm[pc]
        path.append(hex(pc - base))
        op, args = (text.split(None, 1) + [""])[:2]
        nextpc = pc + 4
        if re.match(r"add\s+x22,", text):
            nameaddr = regs["8"] + int(args.rsplit("#", 1)[1], 0)
            name = read(nameaddr, 100).split(b"\0")[0].decode()
            return {
                "code": f"0x{code:08x}",
                "context": context,
                "case_rva": hex(pc - base),
                "kind": "default" if name == "IOCTL UNKNOWN" else "named",
                "name": name,
                "path": path,
                "tables": tables,
            }
        if re.match(r"(mov|ldr)\s+w20,", text):
            value = (
                val(args.split(",")[1])
                if op == "mov"
                else struct.unpack("<I", read(int(args.split(",")[1], 0), 4))[0]
            )
            return {
                "code": f"0x{code:08x}",
                "context": context,
                "case_rva": hex(pc - base),
                "kind": "status",
                "status": f"0x{value:08x}",
                "path": path,
                "tables": tables,
            }
        m = re.fullmatch(
            r"(mov|movk)\s+[wx](\d+), #(0x[0-9a-f]+|\d+)(?:, lsl #(0x[0-9a-f]+))?", text
        )
        if m:
            shift = int(m[4] or "0", 0)
            value = int(m[3], 0) << shift
            regs[m[2]] = value if m[1] == "mov" else (regs[m[2]] & ~(0xFFFF << shift)) | value
        elif op == "cmp":
            parts = args.split(",")
            a = val(parts[0])
            b = val(parts[1])
            b <<= int(parts[2].split("#")[1], 0) if len(parts) > 2 else 0
            flags = (a & 0xFFFFFFFF, b & 0xFFFFFFFF)
        elif op.startswith("b."):
            a, b = flags
            take = {
                "eq": a == b,
                "ne": a != b,
                "hi": a > b,
                "ls": a <= b,
                "lo": a < b,
                "hs": a >= b,
            }[op[2:]]
            if take:
                nextpc = int(args, 0)
        elif op == "b":
            nextpc = int(args, 0)
        elif op in ["adr", "adrp"]:
            dst, number = args.split(",")
            regs[dst.strip()[1:]] = int(number, 0)
        elif op in ["add", "sub"]:
            parts = [x.strip() for x in args.split(",")]
            dst = parts[0]
            value = val(parts[2])
            value <<= int(parts[3].split("#")[1], 0) if len(parts) > 3 else 0
            value = val(parts[1]) + value if op == "add" else val(parts[1]) - value
            regs[dst[1:]] = value & ((1 << (32 if dst[0] == "w" else 64)) - 1)
        elif op in ["ldrsw", "ldrsb"]:
            m = re.fullmatch(r"x(\d+), \[x(\d+), w(\d+), uxtw(?: #(0x[0-9a-f]+))?\]", args)
            assert m, text
            address = regs[m[2]] + (regs[m[3]] << int(m[4] or "0", 0))
            size = 4 if op == "ldrsw" else 1
            regs[m[1]] = int.from_bytes(read(address, size), "little", signed=True)
            tables.append({"entry_rva": hex(address - base), "data": read(address, size).hex()})
        elif op == "br":
            nextpc = regs[args.strip()[1:]]
        elif re.fullmatch(r"mov\s+x25, x0", text):
            pass
        else:
            raise ValueError((hex(pc - base), text))
        pc = nextpc
    raise ValueError(("routing bound", hex(code), context))


expected = []
for context in ["host", "silo"]:
    for low in range(0x10000):
        result = route(0x6D0000 + low, context)
        if result["kind"] != "default" or result["tables"]:
            expected.append(result)
args.output.write_text(json.dumps(expected, indent=2) + "\n")
print(
    "reference routes",
    len(expected),
    "recognized unique codes",
    len({x["code"] for x in expected if x["kind"] != "default"}),
    "table default routes",
    sum(x["kind"] == "default" for x in expected),
)

print(Counter((x["context"], x["kind"]) for x in expected))

if expected != fixture["reference_routing"]:
    raise ValueError("Routing differs from the reviewed fixture")
