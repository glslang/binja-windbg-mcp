# Real analysis captures

The HEVD captures come from the actual Binary Ninja 6.0.10601 Personal GUI on 2026-09-06.
They cover 108 functions from the same ARM64 driver and pin SHA-256, PE/PDB identity and
analysis version. No binary or PDB is included.

- `hevd-arm64-bn6-partial.json` preserves the original unresolved-input result. Its empty
  `expected_mappings` does not establish absence of IOCTLs. BN rendered the input through
  `Parameters.Create` and an unnamed offset; the old adapter could not identify it.
- `hevd-arm64-bn6-ioctls.json` captures the fixed adapter's 29 cases. Expected mappings
  were checked separately against ARM64 comparisons of the input minus `0x222000`, their
  equality edges, and the first case call sites. `reference_control_flow` records those
  branches. The two comparisons that reuse the subtraction across a predecessor block
  were checked through their incoming branch. Expectations were not derived from the
  adapter's map or a published IOCTL table.
- `inputs/hevd-ioctl-input.json` retains the actual database layout and typed input-read
  shape for offline testing of the adapter itself. The matching base type, pointer width,
  component offsets and read width were measured inside BN.

The tests retain per-section results, recovered registrations and imports, device
characteristics, null unproven sizes and bounded traversal. The new input interpretation
is limited to callbacks registered exclusively for device-control major functions.
The [HEVD record](../../docs/hevd-e2e.md) describes both the runtime bridge test and the
subsequent static recovery fix. Static cases are not observed runtime coverage.

For further captures, use `binja_windbg_mcp.fixtures.capture_fixture` from a Binary Ninja
background task on the selected, fully analyzed PE view. Supply independently reviewed
`expected_mappings` with `code`, `dispatch_rva`, and `case_rva`. The helper refuses
incomplete captures and unavailable original bytes. Mocks supplement real captures.

A separate complete mountmgr capture and independently observed runtime access remain
outstanding. This HEVD build does not establish recovery for other drivers or builds.
