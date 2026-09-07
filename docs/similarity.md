# Binary similarity

The optional `similarity` group compares two open Windows PE views or BNDBs using
Binary Ninja 6 Ultimate's Google BinDiff and WARP providers. Personal continues to
support the existing companion tools; `similarity_status` reports unavailable
providers and `similarity_start` returns `status: "unavailable"` there.

This implementation has offline and SDK transport coverage. Native Ultimate runs,
real similarity captures, and the similarity-to-debugger acceptance workflow remain
release gates. The available installation is 6.0.10601 Personal. Its headless
capability probe returned unavailable; that does not validate Ultimate execution.

## Workflow

1. Open both files using native MCP or the Binary Ninja UI and let analysis finish.
2. Use the companion's `list_binaries` to obtain its binary IDs. Native MCP view
   handles are not interchangeable with these IDs.
3. Call `similarity_status` without an ID to check provider availability.
4. Call `similarity_start` with `reference_binary_id` and `target_binary_id`. Both
   views must be PE images of the same architecture. `providers` defaults to
   `["Google BinDiff", "WARP"]`; either provider can also be selected alone.
5. Poll `similarity_status(comparison_id)` until `active` is false. Cancellation
   requests are cooperative: `similarity_cancel` does not imply that BN has stopped.
6. Page `similarity_results(comparison_id)` and inspect a chosen result with
   `similarity_diff(comparison_id, result_id)`.
7. Navigate using the selected side's `binary_id`, `coordinate`, and `generation`
   as `expected_generation`. Then use the existing explicit pairing and debugging
   tools against that build. A match never permits using the reference build's
   identity or RVA against a different loaded module.
8. Call `similarity_close` when finished. Closing a running comparison requests
   cancellation and keeps ownership until the provider finishes.

`groups: "all"` includes these six tools. Explicit group configurations must include
`similarity`; `workspace` remains automatically included. No resolver or provider
apply method is invoked. The companion does not change global WARP settings, enable
network services, transfer annotations, save databases, or execute the debugger as
part of a comparison.

## Results and limits

The comparison ID belongs to this process. Result IDs belong to one comparison.
Status without an ID lists retained comparisons so clients can recover a returned
ID after reconnecting. Listener Stop clears comparisons, requesting cancellation
for active work. A subsequent Start waits for that work to finish before accepting
another comparison. Application quit also requests cancellation and uses the
existing bounded shutdown wait; an unfinished native run remains owned.

| Parameter or resource | Behavior |
|---|---|
| Active comparisons | One per companion process |
| Retained comparisons | Four, including the active comparison; close one when full |
| `timeout_ms` | Default 120,000; accepted range 1–600,000; expiry requests a stop |
| Functions | At most 100,000 per view |
| Stored matches | At most 100,000; reaching the bound reports partial coverage |
| `offset`, `limit` | Nonnegative offset; default limit 100, maximum 500 |
| Page payload | Item list bounded to approximately 256 KiB; follow `next_offset` |
| Disassembly | At most 2,000 instructions per side; instruction text capped at 1,024 characters |

Results are available after a run finishes, including after cancellation or failure.
Status includes `active`, `state`, `stop_reason`, `coverage_complete`, snapshots of
both inputs, and any error. Providers may take time to honor cancellation; the
active slot is not released early. Partial, stale, or unresolved evidence must not
be treated as a complete map.

`similarity_results` accepts `side: "reference" | "target"` (default `target`),
`kind: "matches" | "unmatched"` (default `matches`), an optional `provider`, and
`min_similarity` / `min_confidence` integers from 0 to 255 (default zero).
Matches are ordered by the selected side's RVA, then descending scores. Providers'
scores stay separate; the companion does not turn them into a combined probability.
Competing candidates remain separate. Reciprocal reports of the same provider,
function pair, and scores are deduplicated.

Unmatched listings use every provider selected for the comparison and do not accept
score or provider filters. They mean no retained match was found under that
comparison's coverage, not that a function was definitively added or removed.
Unresolvable or external node references are counted in `unresolved_results` and
never converted to debugger coordinates using names or guessed addresses.

Each match contains separate `reference` and `target` records with binary ID,
generation, image coordinate, address, and name. Status preserves architecture,
PE/PDB identity and available original-file hash for both inputs. An unavailable
hash remains unavailable; PE timestamp and size are matching metadata, not a
cryptographic identity guarantee.

`similarity_diff` aligns instruction text, ignoring each instruction's own address
as a matching key. Rows have `equal`, `insert`, `delete`, or `replace` kinds and
contain the reference and target instruction or `null`. Operands remain literal:
relocations, symbol names and differing branch addresses can produce text changes.
This is an agent-readable textual comparison, not BN's native visual diff or a
semantic equivalence claim. `instructions_truncated` reports capture limits
separately from page truncation. The tool never interprets a missing tail as removed
code.

View changes invalidate comparisons. Historical match records remain inspectable
with `state: "stale"`; new disassembly capture is refused. Navigation with the
captured generation also refuses after rebase, edits, closure, or replacement.

## Ultimate acceptance and captures

Use two disposable, fully analyzed, same-architecture PE fixtures with known
unchanged, relocated, modified and unmatched functions. Test BinDiff and WARP
separately and together. Compare results against independently recorded function
addresses and instructions; check names, types, comments and bytes before and after.
Exercise cancellation on a sufficiently large pair and view edit/rebase/close while
running. Confirm the UI remains responsive and normal application quit succeeds
with a comparison active. Do not infer a universal accuracy guarantee from a fixture.

The opt-in capture runner reads a private JSON connection file containing `url` and
`token`; credentials are never written into its report:

```console
python tools/similarity_capture.py --connection /private/path/companion.json \
  --reference <reference-binary-id> --target <target-binary-id> \
  --output /private/path/similarity-capture.json
```

The report records BN version/capabilities, input snapshots, all retained matches
and unmatched functions, and the first ten disassembly differences. `--diff-count`
accepts 0–100. The runner checks unchanged input generations, identity and modification
state, and closes its comparison on success or failure. It requires both providers
and complete coverage. Retain reviewed captures with known original hashes and
independent expectations as future offline fixtures; no Ultimate capture is
currently claimed or checked in.

Finally, validate target-side navigation followed by an existing identity-guarded
WinDbg operation against a disposable session, including wrong-build refusal.
The current WinDbg coordinate protocol already supplies that guard; this feature
adds no Rust tools or worker calls.

## Sources

- [BN6 announcement](https://binary.ninja/2026/09/03/binary-ninja-6.0-krypton.html#binary-similarity)
- [Binary Similarity guide](https://docs.binary.ninja/guide/similarity.html)
- [Similarity Python API](https://api.binary.ninja/binaryninja.similarity-module.html)
