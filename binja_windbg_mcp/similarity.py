"""Process-local comparison jobs and immutable results. No Binary Ninja import at startup."""

from __future__ import annotations

import copy
import difflib
import json
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from itertools import zip_longest

PROVIDERS = ("Google BinDiff", "WARP")
SIDES = ("reference", "target")
MAX_RESULTS = 100_000
MAX_PAGE_BYTES = 256 * 1024


class SimilarityError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def require(condition, code, message):
    if not condition:
        raise SimilarityError(code, message)


def page(items, offset, limit):
    require(type(offset) is int and offset >= 0, "invalid_params", "offset must be nonnegative")
    require(type(limit) is int and 1 <= limit <= 500, "invalid_params", "limit must be 1–500")
    selected, size = [], 0
    for item in items[offset : offset + limit]:
        encoded_size = len(json.dumps(item, ensure_ascii=True).encode()) + 1
        if selected and size + encoded_size > MAX_PAGE_BYTES:
            break
        selected.append(item)
        size += encoded_size
    end = offset + len(selected)
    return {
        "items": copy.deepcopy(selected),
        "total": len(items),
        "next_offset": end if end < len(items) else None,
        "truncated": end < len(items),
    }


def align_instructions(reference, target):
    """Text alignment only: addresses are retained but never used as matching keys."""
    matcher = difflib.SequenceMatcher(
        None, [r["text"] for r in reference], [r["text"] for r in target], autojunk=False
    )
    rows = []
    for kind, a, b, c, d in matcher.get_opcodes():
        for left, right in zip_longest(reference[a:b], target[c:d]):
            row_kind = "insert" if left is None else "delete" if right is None else kind
            rows.append({"kind": row_kind, "reference": left, "target": right})
    return rows


class MatchIndex:
    """Lazily index frozen results without holding the manager's lifecycle lock."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ordered = {}
        self._filtered = OrderedDict()

    def select(self, records, side, provider, min_similarity, min_confidence):
        with self._lock:
            if side not in self._ordered:
                self._ordered[side] = tuple(
                    sorted(
                        records,
                        key=lambda r: (
                            int(r[side]["coordinate"]["rva"], 16),
                            -r["similarity"],
                            -r["confidence"],
                            r["result_id"],
                        ),
                    )
                )
            ordered = self._ordered[side]
            if provider is None and min_similarity == min_confidence == 0:
                return ordered
            key = (side, provider, min_similarity, min_confidence)
            if key not in self._filtered:
                self._filtered[key] = tuple(
                    r
                    for r in ordered
                    if (provider is None or r["provider"] == provider)
                    and r["similarity"] >= min_similarity
                    and r["confidence"] >= min_confidence
                )
                # Retain row references only, with a bounded cache for arbitrary score queries.
                if len(self._filtered) > 8:
                    self._filtered.popitem(last=False)
            self._filtered.move_to_end(key)
            return self._filtered[key]


@dataclass
class Comparison:
    reference: str
    target: str
    providers: tuple[str, ...]
    timeout_ms: int
    backend_name: str = "native"
    adapter: object = None
    stage: str = "preparing"
    omitted: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    phase: str = "preparing"
    reason: str | None = None
    stale: bool = False
    closing: bool = False
    progress: float = 0.0
    error: dict | None = None
    snapshots: dict = field(default_factory=dict)
    keys: tuple = ()
    records: list = field(default_factory=list)
    match_index: MatchIndex = field(default_factory=MatchIndex)
    unmatched: dict = field(default_factory=lambda: {side: [] for side in SIDES})
    incomplete: bool = True
    unresolved: int = 0
    cancel: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    deadline: float = 0


class SimilarityManager:
    def __init__(self, workspace, backend=None):
        if backend is None:
            from .similarity_backends import SimilarityBackends

            backend = SimilarityBackends(workspace)
        self.backend = backend
        self._lock = threading.RLock()
        self._jobs = {}
        self._accepting = True
        self._shutdown = threading.Event()

    def resume(self):
        with self._lock:
            require(not self._shutdown.is_set(), "shutting_down", "application is shutting down")
            self._accepting = True

    def _get(self, comparison_id):
        require(
            comparison_id in self._jobs, "unknown_comparison", "comparison is closed or unknown"
        )
        return self._jobs[comparison_id]

    def _status(self, job):
        return {
            "comparison_id": job.id,
            "state": "stale" if job.stale else job.phase,
            "active": not job.done.is_set(),
            "closing": job.closing,
            "progress": job.progress,
            "stop_reason": job.reason,
            "providers": list(job.providers),
            "backend": job.backend_name,
            "stage": job.stage,
            "omitted_functions": copy.deepcopy(job.omitted),
            "binary_ids": {"reference": job.reference, "target": job.target},
            "snapshots": copy.deepcopy(job.snapshots),
            "match_count": len(job.records),
            "coverage_complete": not job.incomplete,
            "unresolved_results": job.unresolved,
            "error": copy.deepcopy(job.error),
        }

    def status(self, comparison_id=None):
        if comparison_id is not None:
            with self._lock:
                return self._status(self._get(comparison_id))
        capabilities = self.backend.capabilities()
        with self._lock:
            return {
                "capabilities": capabilities,
                "accepting": self._accepting and not self._shutdown.is_set(),
                "comparisons": [self._status(j) for j in self._jobs.values()],
            }

    def start(
        self,
        reference_binary_id,
        target_binary_id,
        providers=None,
        timeout_ms=120000,
        backend="auto",
    ):
        require(
            bool(reference_binary_id)
            and bool(target_binary_id)
            and reference_binary_id != target_binary_id,
            "invalid_params",
            "select two distinct companion binary IDs",
        )
        requested = providers
        require(backend in ("auto", "native", "external"), "invalid_params", "unknown backend")
        providers = tuple(PROVIDERS if providers is None else providers)
        require(
            bool(providers)
            and len(set(providers)) == len(providers)
            and all(p in PROVIDERS for p in providers),
            "invalid_params",
            "select Google BinDiff, WARP, or both without duplicates",
        )
        require(
            type(timeout_ms) is int and 1 <= timeout_ms <= 600000,
            "invalid_params",
            "timeout_ms must be 1–600000",
        )
        if hasattr(self.backend, "select"):
            backend_name, adapter, providers = self.backend.select(backend, requested)
        else:
            backend_name, adapter = "native", self.backend
            capabilities = adapter.capabilities()
            require(
                backend != "external" and all(capabilities["providers"].get(p) for p in providers),
                "similarity_unavailable",
                "BN6 Ultimate and the requested providers are required: " + ", ".join(providers),
            )
        with self._lock:
            require(
                self._accepting and not self._shutdown.is_set(), "stopping", "listener is stopping"
            )
            require(
                not any(not j.done.is_set() for j in self._jobs.values()),
                "busy",
                "a comparison is still active",
            )
            require(
                len(self._jobs) < 4,
                "comparison_limit",
                "close a retained comparison first (limit 4)",
            )
            job = Comparison(reference_binary_id, target_binary_id, providers, timeout_ms)
            job.backend_name, job.adapter = backend_name, adapter
            job.deadline = time.monotonic() + timeout_ms / 1000
            self._jobs[job.id] = job
            job.thread = threading.Thread(
                target=self._run, args=(job,), name="binja-similarity", daemon=True
            )
            job.thread.start()
            return self._status(job)

    def _stop(self, job, reason):
        if reason == "stale":
            job.stale = True
        if job.reason is None or reason == "stale":
            job.reason = reason
        job.cancel.set()

    def _check(self, job):
        with self._lock:
            if time.monotonic() >= job.deadline:
                self._stop(job, "timed_out")
            if job.cancel.is_set():
                raise SimilarityError(job.reason or "cancelled", "comparison stop requested")

    def _run(self, job):
        run = None
        try:
            run = job.adapter.prepare(
                job.reference, job.target, job.providers, lambda: self._check(job)
            )
            with self._lock:
                job.snapshots = copy.deepcopy(run.snapshots)
                job.keys = tuple(run.keys)
            self._check(job)
            run.validate()
            run.start()
            with self._lock:
                job.phase = "running"
            stop_sent = False
            while not run.finished:
                try:
                    self._check(job)
                except SimilarityError:
                    if not stop_sent:
                        run.request_stop()
                        stop_sent = True
                    with self._lock:
                        job.phase = "stopping"
                with self._lock:
                    job.progress = run.progress
                    job.stage = getattr(run, "stage", "matching")
                time.sleep(0.05)
            # No native objects are released while a provider can still use them.
            if not self._shutdown.is_set():
                with self._lock:
                    job.stage = (
                        getattr(run, "stage", "matching")
                        if getattr(run, "error", None)
                        else "importing"
                    )
                for record in run.records():
                    with self._lock:
                        if job.closing:
                            break
                        if len(job.records) == MAX_RESULTS:
                            job.error = {"code": "result_limit", "message": "result limit reached"}
                            break
                        job.records.append({**record, "backend": job.backend_name})
                else:
                    with self._lock:
                        job.incomplete = job.reason is not None
                with self._lock:
                    job.unresolved = run.unresolved
                    job.omitted = getattr(run, "omitted", {})
                    job.incomplete |= any(job.omitted.values())
                    job.incomplete |= job.unresolved > 0
                    job.unmatched = run.unmatched(job.records)
                try:
                    run.validate()
                except SimilarityError:
                    with self._lock:
                        self._stop(job, "stale")
            with self._lock:
                job.phase = job.reason or (
                    "partial" if job.error or job.incomplete else "completed"
                )
                job.progress = run.progress
        except Exception as error:
            with self._lock:
                code = error.code if isinstance(error, SimilarityError) else "comparison_failed"
                job.error = {
                    "code": code,
                    "message": str(error)
                    if isinstance(error, SimilarityError)
                    else type(error).__name__,
                }
                if code == "stale":
                    job.stale = True
                job.phase = job.reason or "failed"
        finally:
            # Includes exceptions after start: drain cooperatively before dropping handles.
            if run is not None:
                while True:
                    try:
                        run.finish()
                        break
                    except Exception as error:
                        with self._lock:
                            job.phase = "stopping"
                            job.error = {"code": "cleanup_pending", "message": type(error).__name__}
                        time.sleep(0.05)
            with self._lock:
                if run is not None:
                    job.omitted = getattr(run, "omitted", {})
                    job.unresolved = run.unresolved
                if job.error and job.phase == "stopping":
                    job.phase = job.reason or "failed"
                job.incomplete |= job.reason is not None or job.error is not None or job.stale
                job.done.set()
                if job.closing:
                    self._jobs.pop(job.id, None)

    def invalidate(self, key):
        with self._lock:
            for job in self._jobs.values():
                if key in job.keys:
                    self._stop(job, "stale")
                    job.incomplete = True

    def cancel(self, comparison_id):
        with self._lock:
            job = self._get(comparison_id)
            if not job.done.is_set():
                self._stop(job, "cancelled")
            return self._status(job)

    def close(self, comparison_id):
        with self._lock:
            job = self._jobs.get(comparison_id)
            if job is None:
                return {"comparison_id": comparison_id, "state": "closed"}
            job.closing = True
            self._stop(job, "closed")
            if job.done.is_set():
                del self._jobs[job.id]
                return {"comparison_id": comparison_id, "state": "closed"}
            return self._status(job)

    def stop_all(self, shutdown=False):
        with self._lock:
            self._accepting = False
            if shutdown:
                self._shutdown.set()
            for job in list(self._jobs.values()):
                job.closing = True
                self._stop(job, "shutdown" if shutdown else "listener_stopped")
                if job.done.is_set():
                    del self._jobs[job.id]

    def join(self, timeout):
        deadline = time.monotonic() + timeout
        with self._lock:
            threads = [j.thread for j in self._jobs.values()]
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))

    def results(
        self,
        comparison_id,
        side="target",
        kind="matches",
        provider=None,
        min_similarity=0,
        min_confidence=0,
        offset=0,
        limit=100,
    ):
        require(
            side in SIDES and kind in ("matches", "unmatched"),
            "invalid_params",
            "invalid side or kind",
        )
        require(provider is None or provider in PROVIDERS, "invalid_params", "unknown provider")
        require(
            all(type(s) is int and 0 <= s <= 255 for s in (min_similarity, min_confidence)),
            "invalid_params",
            "scores must be integers from 0 to 255",
        )
        require(
            kind != "unmatched" or (provider is None and min_similarity == min_confidence == 0),
            "invalid_params",
            "unmatched uses all selected providers without score filtering",
        )
        with self._lock:
            job = self._get(comparison_id)
            require(
                job.done.is_set(), "not_ready", "wait for comparison completion or cancellation"
            )
        if kind == "matches":
            records = job.match_index.select(
                job.records, side, provider, min_similarity, min_confidence
            )
        else:
            records = job.unmatched[side]
        result = page(records, offset, limit)
        with self._lock:
            # A close/shutdown may have completed while indexing or copying this page.
            self._get(comparison_id)
            return {**self._status(job), "side": side, "kind": kind, **result}

    def diff(self, comparison_id, result_id, offset=0, limit=100):
        with self._lock:
            job = self._get(comparison_id)
            require(job.done.is_set(), "not_ready", "comparison has not finished")
            require(
                not job.stale and not job.closing, "stale", "comparison views changed or closed"
            )
            record = next((r for r in job.records if r["result_id"] == result_id), None)
            require(
                record is not None, "unknown_result", "result does not belong to this comparison"
            )
            record, snapshots = copy.deepcopy(record), copy.deepcopy(job.snapshots)
        try:
            instructions, truncated = job.adapter.instructions(record, snapshots)
        except SimilarityError as error:
            if error.code == "stale":
                with self._lock:
                    self._stop(job, "stale")
            raise
        rows = align_instructions(instructions["reference"], instructions["target"])
        with self._lock:
            require(
                not job.stale and not job.closing and not self._shutdown.is_set(),
                "stale",
                "comparison changed during disassembly capture",
            )
        return {
            "comparison_id": comparison_id,
            "result": record,
            "comparison_kind": "instruction_text",
            "instructions_truncated": truncated,
            **page(rows, offset, limit),
        }
