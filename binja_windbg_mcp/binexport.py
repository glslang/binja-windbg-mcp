"""Versioned, optional in-process export boundary. No BN headless initialization."""

import ctypes
import hashlib
import json
import platform
import secrets
from pathlib import Path

from .similarity import SimilarityError, require

CALLBACK = ctypes.CFUNCTYPE(ctypes.c_bool)
HELPER = Path(__file__).parent / "native" / "libbinja_binexport.dylib"
MAX_EXPORT_BYTES = 256 * 1024 * 1024


class BinExport:
    def __init__(self):
        self._library = None

    def library(self):
        require(
            platform.system() == "Darwin" and platform.machine() == "arm64",
            "similarity_unavailable",
            "export helper currently requires Apple Silicon macOS",
        )
        require(
            HELPER.is_file(),
            "similarity_unavailable",
            "install the companion BinExport helper; see docs/similarity.md",
        )
        from binaryninja import _binaryninjacore as core

        require(
            core.BNIsUIEnabled(),
            "similarity_unavailable",
            "Personal exports run inside the Binary Ninja GUI",
        )
        if self._library is None:
            try:
                library = ctypes.CDLL(str(HELPER))
                library.BNMCPExportABI.restype = ctypes.c_uint32
                library.BNMCPCoreABI.restype = ctypes.c_uint32
                library.BNMCPExportView.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_char_p,
                    ctypes.c_char_p,
                    CALLBACK,
                ]
                library.BNMCPExportView.restype = ctypes.c_void_p
                library.BNMCPFree.argtypes = [ctypes.c_void_p]
                library.BNMCPFree.restype = None
                self._library = library
            except (OSError, AttributeError) as error:
                raise SimilarityError(
                    "similarity_unavailable",
                    "export helper could not load; rebuild for this BN6 installation",
                ) from error
        require(
            self._library.BNMCPExportABI() == 1
            and self._library.BNMCPCoreABI() == core.BNGetCurrentCoreABIVersion(),
            "similarity_unavailable",
            "export helper ABI mismatch; rebuild against this BN6 SDK",
        )
        return self._library

    def capabilities(self):
        try:
            library = self.library()
            return {"available": True, "abi": 1, "core_abi": library.BNMCPCoreABI()}
        except (SimilarityError, ImportError, RuntimeError) as error:
            return {"available": False, "reason": str(error)}

    def export(self, view, destination, check):
        library = self.library()
        check()
        stopped = []

        @CALLBACK
        def keep_going():
            try:
                check()
                return True
            except Exception as error:
                stopped.append(error)
                return False

        export_id = secrets.token_hex(32)
        pointer = library.BNMCPExportView(
            view.handle, str(destination).encode(), export_id.encode(), keep_going
        )
        require(pointer, "export_failed", "export helper returned no result")
        try:
            result = json.loads(ctypes.string_at(pointer))
        finally:
            library.BNMCPFree(pointer)
        if stopped:
            raise stopped[0]
        check()
        require(result.get("ok"), "export_failed", result.get("error", "BinExport failed"))
        require(
            destination.stat().st_size <= MAX_EXPORT_BYTES,
            "export_failed",
            "BinExport exceeds 256 MiB",
        )
        with destination.open("rb") as stream:
            result["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        require(result["export_id"] == export_id, "export_failed", "export identity mismatch")
        result["functions"] = {int(address, 16) for address in result["functions"]}
        return result
