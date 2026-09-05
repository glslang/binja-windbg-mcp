"""Typed, bounded analysis result surface."""

from typing import Literal

from pydantic import BaseModel, Field


class CodeLine(BaseModel):
    address: str
    rva: str
    text: str = Field(max_length=4096)


class CodeResult(BaseModel):
    status: Literal["success", "unavailable"] = "success"
    representation: Literal["disassembly", "llil", "mlil", "hlil"] | None = None
    lines: list[CodeLine] = Field(default_factory=list, max_length=1000)
    truncated: bool = False
    reason: str | None = None


class Edge(BaseModel):
    type: str
    target_rva: str


class Block(BaseModel):
    start_rva: str
    end_rva: str
    edges: list[Edge] = Field(max_length=1000)


class CfgResult(BaseModel):
    blocks: list[Block] = Field(max_length=1000)
    truncated: bool


class Reference(BaseModel):
    kind: Literal["code", "data"]
    rva: str


class XrefResult(BaseModel):
    references: list[Reference] = Field(max_length=1000)
    truncated: bool


class Match(BaseModel):
    kind: Literal["symbol"]
    name: str
    rva: str


class SearchResult(BaseModel):
    matches: list[Match] = Field(max_length=1000)
    truncated: bool
    scope: Literal["symbols"]
