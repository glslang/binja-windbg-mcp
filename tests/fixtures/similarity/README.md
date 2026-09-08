# Personal similarity capture

`personal.json` records real comparisons on BN 6.0.10601 Personal (Apple Silicon),
using the ABI-187 helper and a locally built BinDiff 8 CLI. It contains no tokens.
Opaque binary/comparison IDs and temporary paths were replaced with stable labels;
addresses, identities, scores, differences, and coverage were preserved.

Reproduce with `tools/similarity_gui_smoke.py`, which generates four synthetic
x86-64 PE files. Expected functions: reference/identical/relocated each have entry
RVA `0x1000` and callee RVA `0x1020`; changed has an additional callee at `0x1040`.
The relocated image base is `0x180000000`, versus `0x140000000` for the others.
The changed build alters entry control flow and callee instructions.

The probe checked unchanged function names, types, comments, image bytes, generation
stamps, identities, and modification flags, and navigated to each target's own
coordinate. It did not operate WinDbg. The exact exporter/CLI source provenance and
remaining Ultimate/WinDbg acceptance limits are in the validation document.
