"""Owned BinDiff subprocesses and validated, immutable SQLite result import."""

import copy
import hashlib
import math
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from .binexport import BinExport
from .similarity import MAX_RESULTS, PROVIDERS, SIDES, SimilarityError, require
from .similarity_adapter import NativeSimilarity

MAX_DATABASE_BYTES = 256 * 1024 * 1024


class Process:
    """Drain continuously, retain a bounded tail, and reap only the owned process group."""

    def __init__(self, arguments, directory=None):
        self.output = bytearray()
        self.process = subprocess.Popen(
            arguments,
            cwd=directory,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            while data := self.process.stdout.read(8192):
                self.output.extend(data)
                del self.output[:-65536]
        finally:
            self.process.stdout.close()

    def stop(self):
        # Signal the group even if its leader exited, so a pipe-owning child cannot linger.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(self.process.pid, sig)
            except ProcessLookupError:
                pass
            if sig == signal.SIGTERM:
                self.reader.join(0.5)
        self.process.wait()
        self.reader.join()

    def wait(self, check):
        try:
            while self.process.poll() is None or self.reader.is_alive():
                check()
                time.sleep(0.02)
            check()
            return self.process.returncode
        except BaseException:
            self.stop()
            raise


def executable(path):
    candidate = path if path is not None else shutil.which("bindiff")
    require(
        isinstance(candidate, str) and bool(candidate),
        "similarity_unavailable",
        "install BinDiff 8 and set similarity.bindiff_path or add bindiff to PATH",
    )
    candidate = Path(candidate).expanduser()
    require(
        candidate.is_absolute() and candidate.is_file() and os.access(candidate, os.X_OK),
        "similarity_unavailable",
        "similarity.bindiff_path must name an executable absolute path",
    )
    return candidate.resolve()


def score(value):
    require(
        type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1,
        "invalid_database",
        "BinDiff scores must be finite numbers from 0 to 1",
    )
    return math.floor(value * 255 + 0.5)


def address(value):
    require(
        type(value) is int and -(1 << 63) <= value < (1 << 64),
        "invalid_database",
        "invalid function address",
    )
    return value & ((1 << 64) - 1)


class ExternalSimilarity(NativeSimilarity):
    def __init__(self, workspace, exporter=None):
        super().__init__(workspace)
        self.exporter = exporter or BinExport()
        self.path = None
        self.config_error = None
        self._probe = None
        self._probe_lock = threading.Lock()

    def configure(self, path, error=None):
        with self._probe_lock:
            self.path, self._probe = path, None
            self.config_error = error

    def probe(self):
        with self._probe_lock:
            require(not self.config_error, "similarity_unavailable", self.config_error)
            path = executable(self.path)
            info = path.stat()
            key = (str(path), info.st_mtime_ns, info.st_size)
            if self._probe and self._probe[0] == key:
                return self._probe[1]
            deadline = time.monotonic() + 3

            def check():
                require(
                    time.monotonic() < deadline,
                    "similarity_unavailable",
                    "BinDiff version probe timed out",
                )

            process = Process([str(path), "--version"])
            code = process.wait(check)
            text = process.output.decode(errors="replace")
            version = re.search(r"BinDiff\s+(\d+(?:\.\d+)*)", text, re.I)
            require(
                code == 0 and version and int(version[1].split(".")[0]) >= 8,
                "similarity_unavailable",
                "executable must support the BinDiff 8 CLI",
            )
            result = {"path": str(path), "version": version[1], "available": True}
            self._probe = key, result
            return result

    def capabilities(self):
        exporter = self.exporter.capabilities()
        try:
            binary = self.probe()
        except (SimilarityError, OSError) as error:
            binary = {"available": False, "reason": str(error)}
        available = exporter["available"] and binary["available"]
        return {
            "available": available,
            "providers": {PROVIDERS[0]: available, "WARP": False},
            "exporter": exporter,
            "executable": binary,
            "reason": "; ".join(
                item["reason"] for item in (exporter, binary) if not item["available"]
            ),
        }

    def prepare(self, reference, target, providers, check):
        require(
            tuple(providers) == PROVIDERS[:1],
            "similarity_unavailable",
            "external supports Google BinDiff only",
        )
        views, keys, snapshots, functions = self.capture(reference, target, check)
        return ExternalRun(self, self.probe()["path"], views, keys, snapshots, functions, check)


class ExternalRun:
    def __init__(self, backend, path, views, keys, snapshots, functions, check):
        self.backend, self.path = backend, path
        self.views, self.view_keys = views, keys
        self.snapshots, self.functions = snapshots, functions
        self.keys = tuple(keys.values())
        self.check_job = check
        self.directory = tempfile.TemporaryDirectory(prefix="binja-bindiff-")
        self.root = Path(self.directory.name)
        self.stop = threading.Event()
        self.done = threading.Event()
        self.thread = None
        self.process = None
        self.error = None
        self.stage = "exporting"
        self.progress = None
        self.unresolved = 0
        self.omitted = {}
        self.exports = {}
        self.matched = {side: set() for side in SIDES}
        self.import_complete = False

    def validate(self):
        for side, view in self.views.items():
            require(
                tuple(self.snapshots[side]["generation"])
                == self.backend.workspace.stamp(self.view_keys[side], view),
                "stale",
                "view changed during comparison",
            )

    def check(self):
        self.check_job()
        require(not self.stop.is_set(), "cancelled", "comparison stop requested")
        self.validate()

    def start(self):
        self.thread = threading.Thread(target=self._execute, name="binja-bindiff", daemon=True)
        self.thread.start()

    def _execute(self):
        try:
            for side in SIDES:
                self.check()
                destination = self.root / f"{side}.BinExport"
                self.exports[side] = self.backend.exporter.export(
                    self.views[side], destination, self.check
                )
                self.check()
                exported = self.exports[side]["functions"]
                self.omitted[side] = len(self.functions[side].keys() - exported)
            self.stage = "matching"
            self.process = Process(
                [
                    self.path,
                    "--primary=" + str(self.root / "reference.BinExport"),
                    "--secondary=" + str(self.root / "target.BinExport"),
                    "--output_dir=" + str(self.root),
                    "--output_format=bin",
                    "--ui=false",
                ],
                self.root,
            )
            code = self.process.wait(self.check)
            require(code == 0, "bindiff_failed", f"BinDiff exited with status {code}")
            self.check()
        except Exception as error:
            self.error = error
        finally:
            self.done.set()

    @property
    def finished(self):
        return self.done.is_set()

    def request_stop(self):
        self.stop.set()

    def records(self):
        if self.error:
            raise self.error
        self.check()
        self.stage = "importing"
        files = list(self.root.glob("*.BinDiff"))
        require(
            len(files) == 1, "invalid_database", "expected exactly one completed BinDiff database"
        )
        database = files[0]
        require(
            not database.is_symlink() and database.stat().st_size <= MAX_DATABASE_BYTES,
            "invalid_database",
            "invalid or oversized BinDiff database",
        )
        for side in SIDES:
            with (self.root / f"{side}.BinExport").open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            require(
                digest == self.exports[side]["sha256"],
                "invalid_database",
                "export changed after creation",
            )
        connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")

            def progress():
                try:
                    self.check()
                    return 0
                except SimilarityError:
                    return 1

            connection.set_progress_handler(progress, 1000)
            require(
                connection.execute("PRAGMA quick_check").fetchall() == [("ok",)],
                "invalid_database",
                "BinDiff database integrity check failed",
            )
            for table, required in {
                "metadata": {"file1", "file2", "version"},
                "file": {"id", "filename", "hash"},
                "function": {"id", "address1", "address2", "similarity", "confidence"},
            }.items():
                columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
                require(required <= columns, "invalid_database", "unsupported BinDiff schema")
            metadata = connection.execute("SELECT file1, file2 FROM metadata").fetchall()
            require(
                len(metadata) == 1 and metadata[0][0] != metadata[0][1],
                "invalid_database",
                "invalid input metadata",
            )
            for side, file_id in zip(SIDES, metadata[0]):
                rows = connection.execute(
                    "SELECT filename, hash FROM file WHERE id=?", (file_id,)
                ).fetchall()
                require(
                    len(rows) == 1 and rows[0][1] == self.exports[side]["export_id"],
                    "invalid_database",
                    "BinDiff input ownership mismatch",
                )
            seen = set()
            for index, row in enumerate(
                connection.execute(
                    "SELECT address1, address2, similarity, confidence FROM function ORDER BY address1, address2, id"
                )
            ):
                self.check()
                require(index < MAX_RESULTS, "result_limit", "BinDiff row limit reached")
                left, right = address(row[0]), address(row[1])
                similarity, confidence = score(row[2]), score(row[3])
                require((left, right) not in seen, "invalid_database", "duplicate function pair")
                seen.add((left, right))
                for side, addr in zip(SIDES, (left, right)):
                    self.matched[side].add(addr)
                if any(
                    addr not in self.functions[side] or addr not in self.exports[side]["functions"]
                    for side, addr in zip(SIDES, (left, right))
                ):
                    self.unresolved += 1
                    continue
                yield {
                    "result_id": f"match_{index + 1}",
                    "provider": PROVIDERS[0],
                    "similarity": similarity,
                    "confidence": confidence,
                    "raw_similarity": row[2],
                    "raw_confidence": row[3],
                    "reference": copy.deepcopy(self.functions["reference"][left]),
                    "target": copy.deepcopy(self.functions["target"][right]),
                }
            self.import_complete = True
        except sqlite3.Error as error:
            self.check()
            raise SimilarityError(
                "invalid_database", "invalid or unsupported BinDiff database"
            ) from error
        finally:
            connection.close()

    def unmatched(self, records):
        if not self.import_complete:
            return {side: [] for side in SIDES}
        return {
            side: [
                copy.deepcopy(self.functions[side][addr])
                for addr in sorted(
                    self.functions[side].keys()
                    & self.exports[side]["functions"] - self.matched[side]
                )
            ]
            for side in SIDES
        }

    def finish(self):
        if self.thread:
            if not self.finished:
                self.request_stop()
            self.thread.join()
        self.directory.cleanup()
