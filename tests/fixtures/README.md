# Real analysis acceptance captures

This directory is reserved for immutable captures made by the Binary Ninja 6 adapter.
There are currently **no real driver captures** here. Synthetic tests are in test_core.py
and test_adapter.py and must not be represented as HEVD or mountmgr validation.

Use `binja_windbg_mcp.fixtures.capture_fixture` from a Binary Ninja background task on the
selected, fully analyzed PE view. Pass independently reviewed `expected_mappings` records
with `code`, `dispatch_rva`, and `case_rva`; do not generate expectations from the analyzer
under test. The helper pins original-file SHA-256, architecture, PE identity, and the
Binary Ninja analysis version and refuses incomplete captures or unavailable original bytes.

HEVD acceptance needs its actual analyzed dispatch mapping for the identified build.
Mountmgr needs a complete capture, separate from the abbreviated walkthrough, plus a record
of independently observed runtime access to compare with its static security defaults.
