# Binary similarity

The optional `similarity` group compares two open Windows PE views or BNDBs. BN6
Personal uses automatic BinExport plus a user-installed external BinDiff CLI.
Ultimate also supports the native Google BinDiff and WARP providers.

Real GUI comparisons passed on BN 6.0.10601 Personal with the helper and BinDiff 8:
identical and relocated fixtures each produced two matches; the changed fixture
produced two matches and one unmatched target function. Native Ultimate and the
live WinDbg handoff remain separate acceptance checks.

## Personal setup

Install a BinDiff 8 CLI compatible with your machine. The Java UI is not required.
The companion does not download or install BinDiff. Set an absolute executable path
in the existing private `profiles.json`, preserving its other fields and mode 0600:

```json
{
  "similarity": {
    "bindiff_path": "/absolute/path/to/bindiff"
  }
}
```

Without that setting, discovery uses the BN process's PATH, which can differ from
an interactive shell. Restart BN after changing configuration. An explicit invalid
path never falls back to a different executable.

Install the companion's optional export helper by extracting its helper archive
into the companion checkout, or build it on Apple Silicon with Xcode command-line
tools and CMake 3.25 or newer:

```console
python3 tools/build_binexport.py --package
```

This fetches pinned build dependencies and writes the helper and required license
texts under `binja_windbg_mcp/native/`. The optional archive is under `dist/`.
See [helper build and ABI details](../native/binexport/README.md). BN must be
restarted after replacing a loaded helper. No application files are modified.

`similarity_status` reports `capabilities.backends.native` and `.external`, with
separate exporter/executable readiness and setup errors. The helper runs inside
Personal's GUI, uses ABI 187, and opens no export dialog. An incompatible helper or
missing BinDiff disables external comparisons while other tools remain available.

## Workflow

1. Open both files using native MCP or the Binary Ninja UI and let analysis finish.
2. Use the companion's `list_binaries` to obtain its binary IDs. Native MCP view
   handles are not interchangeable with these IDs.
3. Call `similarity_status` without an ID to check provider availability.
4. Call `similarity_start` with `reference_binary_id` and `target_binary_id`. Both
   views must be PE images of the same architecture. `backend` defaults to `auto`:
   prefer native BinDiff plus WARP when both are available; otherwise use external
   BinDiff. Set `native` or `external` to choose explicitly. With explicit providers,
   auto chooses the first backend supporting all of them. External supports only
   `Google BinDiff`; WARP requires native Ultimate. No fallback occurs after a job
   starts.
5. Poll `similarity_status(comparison_id)` until `active` is false. Cancellation
   requests are cooperative during export/native execution. External matching is
   terminated and reaped before the active slot is released.
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
| Export / database file | Each at most 256 MiB |
| Child output | Continuously drained; retain at most 64 KiB |
| Stored matches | At most 100,000; reaching the bound reports partial coverage |
| `offset`, `limit` | Nonnegative offset; default limit 100, maximum 500 |
| Page payload | Item list bounded to approximately 256 KiB; follow `next_offset` |
| Disassembly | At most 2,000 instructions per side; instruction text capped at 1,024 characters |

Results are available after a run finishes, including after cancellation or failure.
Status includes `active`, `state`, `stop_reason`, `coverage_complete`, snapshots of
both inputs, and any error. `backend` records provenance and `stage` distinguishes
preparation, export, matching and import. External progress is `null` rather than
an invented percentage. `omitted_functions` counts captured BN functions without
exported flow graphs; nonzero counts prevent complete coverage. Providers may take time to honor cancellation; the
active slot is not released early. Partial, stale, or unresolved evidence must not
be treated as a complete map.

`similarity_results` accepts `side: "reference" | "target"` (default `target`),
`kind: "matches" | "unmatched"` (default `matches`), an optional `provider`, and
`min_similarity` / `min_confidence` integers from 0 to 255 (default zero).
Matches are ordered by the selected side's RVA, then descending scores. Providers'
scores stay separate; the companion does not turn them into a combined probability.
Completed and partial result ordering is cached per side; repeated filtered pages
reuse a bounded cache of row selections. Indexing and page copying do not hold the
comparison lifecycle lock, so status and close requests can continue.
External `raw_similarity` and `raw_confidence` retain BinDiff's `0–1` values;
integer scores use `floor(raw * 255 + 0.5)`. These scores do not establish equivalence
between backend versions. Competing candidates remain separate. Reciprocal reports of the same provider,
function pair, and scores are deduplicated.

Unmatched listings use every provider selected for the comparison and do not accept
score or provider filters. They mean no retained match was found under that
comparison's coverage, not that a function was definitively added or removed.
For external comparisons, unmatched lists use exported eligible functions only;
functions omitted from export are separate. An interrupted or invalid database
never supplies an unmatched list. Each export uses a unique application-defined
identifier echoed by the BinDiff database; it is not the original-file hash.
Export file hashes and generation checks bind outputs to the selected views.

Unresolvable or external node references are counted in `unresolved_results` and
never converted to debugger coordinates using names or guessed addresses.

Each match contains separate `reference` and `target` records with binary ID,
generation, image coordinate, address, and name. Status preserves architecture,
PE/PDB identity and available original-file hash for both inputs. An unavailable
hash remains unavailable; PE timestamp and size are matching metadata, not a
cryptographic identity guarantee.

`similarity_diff` aligns instruction text, ignoring each instruction's own address
as a matching key. Rows have `equal`, `insert`, `delete`, or `replace` kinds and
contain the reference and target instruction or `null`. A `replace` row always has
both instructions; extra instructions in unequal replacement spans are `insert`
or `delete` rows. Operands remain literal:
relocations, symbol names and differing branch addresses can produce text changes.
This is an agent-readable textual comparison, not BN's native visual diff or a
semantic equivalence claim. `instructions_truncated` reports capture limits
separately from page truncation. The tool never interprets a missing tail as removed
code.

View changes invalidate comparisons. Historical match records remain inspectable
with `state: "stale"`; new disassembly capture is refused. Navigation with the
captured generation also refuses after rebase, edits, closure, or replacement.

## Acceptance and captures

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
state, and closes its comparison on success or failure. Choose `--backend external`
for Personal, or `--backend native` and optionally `--provider WARP` for native
acceptance. Defaults follow backend selection; full coverage is required.
The capture polling deadline is `--timeout-ms` plus 30 seconds for cleanup grace.
Once comparison polling completes, downloading results and disassembly pages is
outside that deadline. The comparison is still closed if report collection fails.

The synthetic Personal capture and independent assertions are checked in under
`tests/fixtures/similarity/`. To reproduce GUI exports, comparisons and navigation,
use an empty BN6 GUI and run in its Python console (choose a new output directory):

```python
from tools.similarity_gui_smoke import start

start("/absolute/path/to/bindiff", "/private/tmp/new-similarity-capture")
```

The companion checkout must be on that console's import path. The probe opens four
small synthetic PE files, exports and compares them, navigates to target results,
and records whether names, types, comments, bytes, generations and identities remain
unchanged. It writes `result.json` and leaves the views open. This probe neither
launches nor executes WinDbg. No Ultimate capture is claimed.

Finally, validate target-side navigation followed by an existing identity-guarded
WinDbg operation against a disposable session, including wrong-build refusal.
The current WinDbg coordinate protocol already supplies that guard; this feature
adds no Rust tools or worker calls.

## Sources

- [BN6 announcement](https://binary.ninja/2026/09/03/binary-ninja-6.0-krypton.html#binary-similarity)
- [Binary Similarity guide](https://docs.binary.ninja/guide/similarity.html)
- [Similarity Python API](https://api.binary.ninja/binaryninja.similarity-module.html)
