# Fix AArch64 CLRBHB decoding and lifting

## Problem and change

The generated decoder recognizes `D50322DF`, but operand conversion omits
`ENC_CLRBHB_HI_HINTS`, so decomposition returns `-9`. Binary Ninja displays no
instruction text and analysis stops at the instruction.

Add the encoding to the zero-operand conversion cases and lift it to a named
`SystemHintOp_CLRBHB` intrinsic, following neighboring hint instructions. Add
disassembly and LLIL regression cases. A `CLRBHB; ADD; RET` fixture now has all
three instructions and continues through the intrinsic.

## Validation

Built a replacement ARM64 architecture plugin against the installed 6.0.10601 SDK
and ran it in a disposable Personal GUI profile with the bundled plugin disabled.
The loaded-image check confirms the replacement supplied the architecture.

- CLRBHB text, four-byte instruction information and named LLIL intrinsic pass.
- All sixteen affected Secure Kernel entries become complete 12-byte functions.
- External BinDiff completes with zero omitted functions, all eight endpoint diffs
  readable, and input/analysis preservation checks passing.
- Standalone CLRBHB, NOP and CSDB decoder regressions pass.
- The GUI exits normally without forced termination or a crash report.

## Before submission

This is a local draft, not a submitted PR. `clrbhb.patch` applies to SDK revision
`2ddf304b3275aa184e95570404539cbc4beb64c6`. Rebase it onto the current development
branch and run the full upstream architecture suite there. The replacement
package remains maintained by binja-windbg-mcp until an upstream release passes
the same native acceptance. See [the complete evidence](../../docs/clrbhb-native-acceptance.md).
