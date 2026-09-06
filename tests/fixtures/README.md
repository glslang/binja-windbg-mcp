# Real analysis captures

`hevd-arm64-bn6-partial.json` was captured from the actual Binary Ninja 6.0.10601 Personal
GUI on 2026-09-06. It contains all 108 function captures from the identified ARM64 HEVD
build, with SHA-256, PE/PDB identity and analysis version. No binary or PDB is included.

This is a **partial-analysis regression fixture**, not complete IOCTL acceptance. Its
empty `expected_mappings` preserves the observed refusal to infer cases from an unresolved
input. Binary Ninja renders that input through the `Parameters.Create` union alternative
and an unnamed offset; the adapter cannot establish `DeviceIoControl.IoControlCode`.
The test separately asserts the three dispatch registrations, five sink imports, device
characteristics, explicit unresolved switch and bounded traversal. The create/close
routine was also exercised against the matching live driver; see the
[HEVD E2E record](../../docs/hevd-e2e.md).

For complete mapping acceptance, use `binja_windbg_mcp.fixtures.capture_fixture` from a
Binary Ninja background task on the selected, fully analyzed PE view. Supply independently
reviewed `expected_mappings` with `code`, `dispatch_rva`, and `case_rva`; do not generate
expectations from the analyzer under test. The helper refuses incomplete captures and
unavailable original bytes. Mocks supplement real captures.

Complete HEVD IOCTL recovery and a separate full mountmgr capture remain outstanding.
Mountmgr acceptance also needs independently observed runtime access to compare with
static security defaults.
