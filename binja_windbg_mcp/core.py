"""Immutable coordinates and bounded analysis records; independent of Binary Ninja."""

from __future__ import annotations

import hashlib
import struct
import time
import uuid
from dataclasses import dataclass, field
from threading import Event
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timestamp: int = Field(ge=0, le=0xFFFFFFFF)
    size: int = Field(gt=0, le=0xFFFFFFFF)
    pdb: dict | None = None


class Coordinate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    module: str = Field(min_length=1, max_length=256)
    image_name: str = Field(min_length=1, max_length=256)
    identity: Identity
    rva: str = Field(pattern=r"^0x[0-9a-f]+$", max_length=18)

    def address(self, base: int, identity: Identity, size: int = 1) -> int:
        if (self.identity.timestamp, self.identity.size) != (identity.timestamp, identity.size):
            raise ValueError("PE identity mismatch")
        if self.identity.pdb and identity.pdb:
            if self.identity.pdb.get("unmatched") or identity.pdb.get("unmatched"):
                raise ValueError("unmatched PDB identity")
            if (self.identity.pdb.get("guid", "").casefold(), self.identity.pdb.get("age")) != (
                identity.pdb.get("guid", "").casefold(),
                identity.pdb.get("age"),
            ):
                raise ValueError("PDB identity mismatch")
        rva = int(self.rva, 16)
        if size < 0 or rva >= identity.size or rva + size > identity.size:
            raise ValueError("range outside image")
        if base < 0 or base + rva + size > 1 << 64:
            raise ValueError("address overflow")
        return base + rva


def pe_identity(read) -> tuple[Identity, str]:
    """read is a raw-file reader, unaffected by a rebased mapped view."""
    dos = bytes(read(0, 64))
    if len(dos) != 64 or dos[:2] != b"MZ":
        raise ValueError("PE DOS header unavailable")
    offset = struct.unpack_from("<I", dos, 60)[0]
    if offset > 16 * 1024 * 1024:
        raise ValueError("PE header offset exceeds bound")
    header = bytes(read(offset, 88))
    if len(header) != 88 or header[:4] != b"PE\0\0":
        raise ValueError("PE header unavailable")
    (machine,) = struct.unpack_from("<H", header, 4)
    optional_size, magic = (
        struct.unpack_from("<H", header, 20)[0],
        struct.unpack_from("<H", header, 24)[0],
    )
    if optional_size < 64 or magic not in (0x10B, 0x20B):
        raise ValueError("unsupported PE optional header")
    (timestamp,) = struct.unpack_from("<I", header, 8)
    (size,) = struct.unpack_from("<I", header, 80)
    return Identity(timestamp=timestamp, size=size, pdb=_pe_pdb(read, offset, header)), {
        0x8664: "x86_64",
        0x14C: "x86",
        0xAA64: "aarch64",
    }.get(machine, hex(machine))


def _pe_pdb(read, pe_offset, header):
    optional_size = struct.unpack_from("<H", header, 20)[0]
    magic = struct.unpack_from("<H", header, 24)[0]
    directories = 112 if magic == 0x20B else 96
    if optional_size < directories + 7 * 8:
        return None
    debug = bytes(read(pe_offset + 24 + directories + 6 * 8, 8))
    if len(debug) != 8:
        return None
    rva, size = struct.unpack("<II", debug)
    if not rva or size > 28 * 256:
        return None
    sections = struct.unpack_from("<H", header, 6)[0]
    if sections > 96:
        return None
    for index in range(sections):
        section = bytes(read(pe_offset + 24 + optional_size + 40 * index, 40))
        if len(section) != 40:
            return None
        va, raw_size, raw_offset = struct.unpack_from("<III", section, 12)
        if not va <= rva < va + raw_size or rva + size > va + raw_size:
            continue
        entries = bytes(read(raw_offset + rva - va, size))
        for offset in range(0, len(entries) - 27, 28):
            kind, length, _, pointer = struct.unpack_from("<IIII", entries, offset + 12)
            if kind != 2 or length < 24:
                continue
            codeview = bytes(read(pointer, 24))
            if len(codeview) == 24 and codeview[:4] == b"RSDS":
                return {
                    "guid": uuid.UUID(bytes_le=codeview[4:20]).hex.upper(),
                    "age": struct.unpack_from("<I", codeview, 20)[0],
                }
    return None


class IoctlCase(BaseModel):
    code: str
    device_type: int
    function: int
    method: Literal["buffered", "in_direct", "out_direct", "neither"]
    required_access: Literal["any", "read", "write", "read_write"]
    dispatch_rva: str
    case_rva: str
    in_size: int | None = None
    out_size: int | None = None
    evidence: list[dict] = Field(default_factory=list)


def ioctl_case(code: int, dispatch: int, site: int, evidence=()) -> dict:
    if not 0 <= code <= 0xFFFFFFFF:
        raise ValueError("IOCTL must fit u32")
    return IoctlCase(
        code=f"0x{code:08x}",
        device_type=code >> 16,
        function=(code >> 2) & 0xFFF,
        method=("buffered", "in_direct", "out_direct", "neither")[code & 3],
        required_access=("any", "read", "write", "read_write")[(code >> 14) & 3],
        dispatch_rva=hex(dispatch),
        case_rva=hex(site),
        evidence=list(evidence),
    ).model_dump()


@dataclass
class Budget:
    seconds: float = 15
    cancel: Event = field(default_factory=Event)
    end: float = field(init=False)

    def __post_init__(self):
        self.end = time.monotonic() + min(max(self.seconds, 0.01), 120)

    def check(self):
        if self.cancel.is_set():
            raise InterruptedError("analysis cancelled")
        if time.monotonic() >= self.end:
            raise TimeoutError("analysis deadline")


def compare_bytes(static: bytes, runtime: bytes, requested: int, relocations: list[dict]) -> dict:
    return dict(
        source="current BinaryView",
        requested_size=requested,
        static_data=static.hex(),
        runtime_data=runtime.hex(),
        static_read_size=len(static),
        runtime_read_size=len(runtime),
        incomplete=len(static) != requested or len(runtime) != requested,
        equal=len(static) == len(runtime) == requested and static == runtime,
        differing_offsets=[i for i, (a, b) in enumerate(zip(static, runtime)) if a != b],
        relocation_ranges=relocations,
    )


def original_hash(view) -> str | None:
    """Only a provably original Raw view is hashed; never reopen a possibly replaced path."""
    raw = view.file.raw
    if raw is None or raw.modified or view.file.filename.lower().endswith(".bndb"):
        return None
    digest = hashlib.sha256()
    for offset in range(0, len(raw), 1024 * 1024):
        size = min(1024 * 1024, len(raw) - offset)
        data = bytes(raw.read(offset, size))
        if len(data) != size:
            return None
        digest.update(data)
    return digest.hexdigest()
