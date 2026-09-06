"""Binary Ninja 6 UI boundary. View references live only for the duration of a job."""

from __future__ import annotations

import asyncio
import copy
import json
import threading
import uuid
import weakref
from pathlib import Path

from . import analysis
from .core import Budget, Coordinate, original_hash, pe_identity


def main_thread(fn, cancel=None):
    import binaryninja as bn

    def check_open():
        if cancel is not None and cancel.is_set():
            raise InterruptedError("Binary Ninja is shutting down")

    check_open()
    if bn.is_main_thread():
        return fn()
    result = []
    finished = threading.Event()

    def run():
        try:
            check_open()
            result.append((True, fn()))
        except Exception as error:
            result.append((False, error))
        finally:
            finished.set()

    bn.execute_on_main_thread(run)
    # Application shutdown must release workers even after Qt stops dispatching.
    while not finished.wait(0.05):
        check_open()
    ok, value = result[0]
    if not ok:
        raise value
    return value


class Workspace:
    def __init__(self):
        self._ids = {}
        self._revision = {}
        self._notifications = {}
        self._waiters = {}
        self._cache = {}
        self._lock = threading.RLock()
        self._closing = threading.Event()
        self._budgets = {}

    def shutdown(self):
        self._closing.set()
        with self._lock:
            for budget in self._budgets.values():
                budget.cancel.set()
            for waiting in self._waiters.values():
                for loop, future in waiting:
                    try:
                        loop.call_soon_threadsafe(future.cancel)
                    except RuntimeError:
                        pass  # The network loop has already closed.
            self._cache.clear()

    def _check_open(self):
        if self._closing.is_set():
            raise InterruptedError("Binary Ninja is shutting down")

    def attach_ui_notifications(self):
        from binaryninjaui import UIContext, UIContextNotification

        owner = self

        class Lifecycle(UIContextNotification):
            def OnAfterCloseFile(self, *args):
                owner._views()

            def OnDataViewReplaced(self, *args):
                for key in list(owner._ids):
                    owner.invalidate(key)
                owner._views()

        self._ui_notification = Lifecycle()
        UIContext.registerNotification(self._ui_notification)

    def invalidate(self, key):
        with self._lock:
            self._revision[key] = self._revision.get(key, 0) + 1
            self._cache.clear()

    def _views(self):
        if self._closing.is_set():
            return []
        from binaryninjaui import FileContext, UIContext

        active = UIContext.activeContext()
        frame = active.getCurrentViewFrame() if active else None
        selected = frame.getCurrentBinaryView() if frame else None
        views = []
        seen = set()
        for context in FileContext.getOpenFileContexts():
            for view in context.getAllDataViews():
                if view.view_type != "PE":
                    continue
                key = (view.file.session_id, view.view_type)
                if key in seen:
                    continue
                seen.add(key)
                with self._lock:
                    self._ids.setdefault(key, uuid.uuid4().hex)
                    self._revision.setdefault(key, 0)
                self._observe(key, view)
                views.append(
                    (
                        key,
                        view,
                        selected is not None and view == selected,
                        frame.getCurrentOffset()
                        if selected is not None and view == selected
                        else None,
                    )
                )
        with self._lock:
            for key in set(self._ids) - seen:
                del self._ids[key]
                self.invalidate(key)
                previous = self._notifications.pop(key, None)
                if previous and previous[1]() is not None:
                    previous[1]().unregister_notification(previous[0])
                for loop, future in self._waiters.pop(key, []):

                    def closed(future=future):
                        if not future.done():
                            future.set_exception(ValueError("view closed"))

                    loop.call_soon_threadsafe(closed)
        return views

    def _observe(self, key, view):
        if key in self._notifications and self._notifications[key][1]() is not None:
            return
        import binaryninja as bn

        owner = self

        class Changed(bn.BinaryDataNotification):
            def data_written(self, *args):
                owner.invalidate(key)

            def data_inserted(self, *args):
                owner.invalidate(key)

            def data_removed(self, *args):
                owner.invalidate(key)

            def function_updated(self, *args):
                owner.invalidate(key)

            def function_added(self, *args):
                owner.invalidate(key)

            def function_removed(self, *args):
                owner.invalidate(key)

            def symbol_updated(self, *args):
                owner.invalidate(key)

            def symbol_added(self, *args):
                owner.invalidate(key)

            def symbol_removed(self, *args):
                owner.invalidate(key)

            def type_defined(self, *args):
                owner.invalidate(key)

            def type_undefined(self, *args):
                owner.invalidate(key)

        event = Changed()
        view.register_notification(event)
        self._notifications[key] = (event, weakref.ref(view))

    def acquire(self, binary_id):
        views = main_thread(self._views, cancel=self._closing)
        candidates = (
            [v for v in views if self._ids[v[0]] == binary_id]
            if binary_id
            else [v for v in views if v[2]]
        )
        if len(candidates) != 1:
            raise ValueError("select one unambiguous open PE binary_id")
        key, view, active, cursor = candidates[0]
        return key, view, active, cursor

    def stamp(self, key, view):
        with self._lock:
            return (self._ids.get(key), view.start, self._revision.get(key, 0))

    def metadata(self, key, view, active):
        self._check_open()
        raw = view.file.raw
        identity, architecture = pe_identity(raw.read)
        hash_key = (self.stamp(key, view), "file_hash")
        with self._lock:
            known_hash = hash_key in self._cache
            digest = self._cache.get(hash_key)
        if not known_hash:
            digest = original_hash(view, cancel=self._closing)
            with self._lock:
                self._cache[hash_key] = digest
        return {
            "file_sha256": digest,
            "hash_source": "original Raw view" if digest else "unavailable",
            "image_name": Path(view.file.original_filename).name.removesuffix(".bndb"),
            "binary_id": self._ids[key],
            "path": view.file.filename,
            "display_name": Path(view.file.filename).name,
            "active": active,
            "architecture": architecture,
            "analysis_state": view.analysis_state.name,
            "image_base": f"0x{view.start:016x}",
            "identity": identity.model_dump(),
            "generation": self.stamp(key, view),
            "modified": view.modified,
        }

    def list_binaries(self):
        return {
            "binaries": [
                self.metadata(k, v, a)
                for k, v, a, _ in main_thread(self._views, cancel=self._closing)
            ]
        }

    def current_location(self, binary_id=None):
        key, view, active, cursor = self.acquire(binary_id)
        result = self.metadata(key, view, active)
        result["coordinate"] = (
            self.coordinate(view, cursor).model_dump() if active and cursor is not None else None
        )
        result["address"] = f"0x{cursor:016x}" if cursor is not None else None
        return result

    def coordinate(self, view, address):
        identity, _ = pe_identity(view.file.raw.read)
        image = Path(view.file.original_filename).name
        if image.lower().endswith(".bndb"):
            image = image[:-5]
        value = Coordinate(
            module=Path(image).stem,
            image_name=image,
            identity=identity,
            rva=hex(address - view.start),
        )
        value.address(view.start, identity)
        if not view.is_valid_offset(address):
            raise ValueError("unmapped destination")
        return value

    def navigate(self, binary_id, coordinate, expected_generation=None, still_valid=None):
        def action():
            if still_valid is not None and not still_valid():
                raise ValueError("pairing closed")
            key, view, _, _ = self.acquire(binary_id)
            if expected_generation is not None and tuple(expected_generation) != self.stamp(
                key, view
            ):
                raise ValueError("view generation changed")
            identity, _ = pe_identity(view.file.raw.read)
            address = coordinate.address(view.start, identity)
            if not view.is_valid_offset(address):
                raise ValueError("unmapped destination")
            if not view.navigate(view.view, address):
                raise ValueError("navigation failed")
            return {"address": f"0x{address:016x}", "coordinate": coordinate.model_dump()}

        return main_thread(action, cancel=self._closing)

    async def wait_for_analysis(self, binary_id, timeout_ms=30000):
        key, view, _, _ = await asyncio.to_thread(self.acquire, binary_id)
        loop = asyncio.get_running_loop()
        done = loop.create_future()

        def complete():
            def resolve():
                if not done.done():
                    done.set_result(True)

            loop.call_soon_threadsafe(resolve)

        with self._lock:
            self._check_open()
            self._waiters.setdefault(key, []).append((loop, done))
        event = None
        try:
            event = view.add_analysis_completion_event(complete)
            # Completion subscriptions report future analysis. Check after subscribing
            # so an already idle view (or a completion racing registration) returns.
            if view.analysis_state.name == "IdleState":
                complete()
            await asyncio.wait_for(done, min(max(timeout_ms, 1), 120000) / 1000)
            await asyncio.to_thread(self.acquire, binary_id)
            return {"status": "success"}
        finally:
            if event is not None:
                event.cancel()
            with self._lock:
                waiting = self._waiters.get(key, [])
                if (loop, done) in waiting:
                    waiting.remove((loop, done))

    def query(self, name, binary_id, *, depth=2, function_limit=128, traverse=False, budget=None):
        if name not in analysis.DRIVER_TOOLS:
            raise ValueError("general analysis belongs to Binary Ninja's native MCP server")
        budget = budget or Budget()
        with self._lock:
            self._check_open()
            self._budgets[id(budget)] = budget
        try:
            return self._query(name, binary_id, depth, function_limit, traverse, budget)
        finally:
            with self._lock:
                self._budgets.pop(id(budget), None)

    def _query(self, name, binary_id, depth, function_limit, traverse, budget):
        key, view, _, _ = self.acquire(binary_id)
        stamp = self.stamp(key, view)
        identity, _ = pe_identity(view.file.raw.read)
        cache_key = (stamp, identity.model_dump_json(), name, depth, function_limit, traverse)
        with self._lock:
            cached = self._cache.get(cache_key)
        if cached is not None:
            latest_key, latest_view, _, _ = self.acquire(binary_id)
            if latest_key != key or self.stamp(latest_key, latest_view) != stamp:
                raise ValueError("cached analysis became stale")
            budget.check()
            return copy.deepcopy(cached)
        capture = capture_driver(view, budget, imports_only=name == "sink_imports")
        options = (
            {"depth": depth, "function_limit": function_limit}
            if name in ("ioctl_map", "driver_surface")
            else {}
        )
        if name == "ioctl_map":
            options["traverse"] = traverse
        # Retained facts can still form partial sections when capture reached its deadline.
        result = getattr(analysis, name)(
            capture, Budget(seconds=2, cancel=budget.cancel), **options
        )
        if capture.get("truncated"):
            result["capture_truncated"] = True
            result["capture_stop"] = capture.get("capture_stop", "function or fact limit")
            if name != "driver_surface":
                result["status"] = "partial"
        current_key, current_view, _, _ = self.acquire(binary_id)
        if key != current_key or stamp != self.stamp(current_key, current_view):
            raise ValueError("analysis became stale; repeat on the current view")
        with self._lock:
            if len(self._cache) >= 32:
                self._cache.clear()
            self._cache[cache_key] = copy.deepcopy(result)
        return result

    def add_evidence(self, binary_id, coordinate, evidence, expected_generation):
        def action():
            key, view, _, _ = self.acquire(binary_id)
            if tuple(expected_generation) != self.stamp(key, view):
                raise ValueError("view generation changed before evidence edit")
            identity, _ = pe_identity(view.file.raw.read)
            address = coordinate.address(view.start, identity)
            actual = self.coordinate(view, address)
            image = coordinate.image_name.replace("\\", "/").rsplit("/", 1)[-1]
            if image.casefold() != actual.image_name.casefold():
                raise ValueError("evidence image name mismatch")
            record = dict(evidence, coordinate=actual.model_dump())
            undo = view.begin_undo_actions()
            try:
                previous = view.get_comment_at(address)
                view.set_comment_at(
                    address,
                    (previous + "\n" if previous else "")
                    + "[windbg-evidence] "
                    + json.dumps(record, sort_keys=True),
                )
                view.commit_undo_actions(undo)
            except BaseException:
                view.revert_undo_actions(undo)
                raise
            self.invalidate(key)
            return {"status": "success", "coordinate": actual.model_dump()}

        return main_thread(action, cancel=self._closing)

    def byte_snapshot(self, binary_id, size):
        key, view, active, cursor = self.acquire(binary_id)
        if not active or cursor is None:
            raise ValueError("cursor must belong to paired view")
        coordinate = self.coordinate(view, cursor)
        coordinate.address(view.start, coordinate.identity, size)
        ranges = [
            {"offset": start - cursor, "size": end - start}
            for start, end in view.relocation_ranges_in_range(cursor, size)
        ]
        return {
            "coordinate": coordinate.model_dump(),
            "data": bytes(view.read(cursor, size)).hex(),
            "modified": view.modified,
            "generation": self.stamp(key, view),
            "relocations": ranges,
        }


def _op(node):
    return getattr(getattr(node, "operation", None), "name", "")


def _constant(node):
    if _op(node) in ("MLIL_CONST", "MLIL_CONST_PTR", "HLIL_CONST", "HLIL_CONST_PTR", "HLIL_IMPORT"):
        return node.constant
    return None


def _field_path(node, depth=0):
    """Accept named structure fields only; numeric offsets without layouts prove nothing."""
    if depth > 12:
        return None
    operation = _op(node)
    if operation in ("HLIL_DEREF_FIELD", "HLIL_STRUCT_FIELD"):
        source = node.src
        value_type = source.expr_type
        if value_type is None:
            return None
        if operation == "HLIL_DEREF_FIELD":
            value_type = value_type.target
        if value_type is None:
            return None
        try:
            member = next(m for m in value_type.members if m.offset == node.offset)
        except (AttributeError, StopIteration):
            return None
        prefix = _field_path(source, depth + 1)
        return (prefix + "." if prefix else "") + member.name
    return None


def _walk(node, budget, depth=0):
    if depth > 64:
        return
    budget.check()
    yield node
    for operand in getattr(node, "operands", []):
        for child in operand if isinstance(operand, list) else [operand]:
            if hasattr(child, "operation"):
                yield from _walk(child, budget, depth + 1)


def capture_driver(view, budget, imports_only=False):
    """Capture structured HLIL facts; unresolved facts remain explicit in format v1."""
    import binaryninja as bn

    imports = {
        s.raw_name: hex(s.address - view.start)
        for s in view.get_symbols()
        if s.type in (bn.SymbolType.ImportedFunctionSymbol, bn.SymbolType.ImportAddressSymbol)
    }
    layouts = {}
    missing = []
    for name, required in (
        ("_DRIVER_OBJECT", {"MajorFunction"}),
        ("_IO_STACK_LOCATION", {"Parameters"}),
        ("_UNICODE_STRING", {"Length", "Buffer"}),
    ):
        value = view.get_type_by_name(name)
        members = {m.name: m.offset for m in getattr(value, "members", [])} if value else {}
        if not required <= members.keys():
            missing.append(name)
        else:
            layouts[name] = members
    result = {
        "format_version": 1,
        "analysis_version": bn.core_version(),
        "architecture": view.arch.name,
        "entry_rva": hex(view.entry_point - view.start),
        "imports": imports,
        "functions": [],
        "types": {
            "provider": "database",
            "architecture": view.arch.name,
            "validated_layouts": layouts,
            "missing": missing,
        },
    }
    if imports_only:
        return result
    for function in view.functions:
        if (
            len(result["functions"]) >= 1024
            or sum(
                len(row.get(key, []))
                for row in result["functions"]
                for key in ("registrations", "control_cases", "calls", "unresolved")
            )
            >= 4096
        ):
            result["truncated"] = True
            break
        try:
            budget.check()
            result["functions"].append(_capture_function(view, function, layouts, budget))
        except (TimeoutError, InterruptedError) as error:
            result["truncated"] = True
            result["capture_stop"] = str(error)
            break
        except Exception as error:
            result["functions"].append(
                {
                    "rva": hex(function.start - view.start),
                    "unresolved": [
                        {
                            "reason": "adapter could not recover function",
                            "error_type": type(error).__name__,
                        }
                    ],
                }
            )
    return result


def _capture_function(view, function, layouts, budget):
    row = {
        "rva": hex(function.start - view.start),
        "registrations": [],
        "control_cases": [],
        "calls": [],
        "unresolved": [],
    }
    il = function.hlil
    if il is None:
        row["unresolved"].append({"reason": "HLIL unavailable", "function_rva": row["rva"]})
        return row
    # SSA identity is preferable to a variable's user-controlled display name.
    inputs = set()
    from itertools import islice

    nodes = list(islice(_walk(il.root, budget), 50001))
    if len(nodes) > 50000:
        row["unresolved"].append({"reason": "function IL node cap"})
        return row
    for node in nodes:
        if (
            _op(node) == "HLIL_VAR_INIT"
            and _field_path(node.src) == "Parameters.DeviceIoControl.IoControlCode"
        ):
            inputs.add(node.dest.identifier)

    for node in nodes:
        if _op(node) == "HLIL_ASSIGN" and _op(node.dest) == "HLIL_VAR":
            inputs.discard(node.dest.var.identifier)

    def is_control(node):
        return _field_path(node) == "Parameters.DeviceIoControl.IoControlCode" or (
            _op(node) == "HLIL_VAR" and node.var.identifier in inputs
        )

    for node in nodes:
        budget.check()
        if (
            sum(len(row[key]) for key in ("registrations", "control_cases", "calls", "unresolved"))
            >= 512
        ):
            row["unresolved"].append({"reason": "function fact cap"})
            break
        operation = _op(node)
        site = hex(node.address - view.start)
        if operation in ("HLIL_CALL", "HLIL_TAILCALL"):
            dest = _constant(node.dest)
            if dest is None:
                continue
            symbol = view.get_symbol_at(dest)
            name = symbol.raw_name if symbol else None
            args = []
            for param in node.params[:16]:
                value = _constant(param)
                literal = view.get_string_at(value) if value is not None else None
                args.append(
                    {"constant": value, "literal": literal.value[:512] if literal else None}
                )
            row["calls"].append(
                {
                    "site": site,
                    "name": name,
                    "target_rva": hex(dest - view.start),
                    "arguments": args,
                    **(_security_arguments(view, name, args) if name in analysis.SECURITY else {}),
                }
            )
        elif operation == "HLIL_ASSIGN" and _op(node.dest) == "HLIL_ARRAY_INDEX":
            array = node.dest
            if _field_path(array.src) != "MajorFunction" or "_DRIVER_OBJECT" not in layouts:
                continue
            index, callback = _constant(array.index), _constant(node.src)
            if index is not None and 0 <= index <= 27:
                row["registrations"].append(
                    {
                        "framework": "WDM",
                        "major_function": index,
                        "registration_rva": site,
                        "callback_rva": hex(callback - view.start)
                        if callback is not None and view.get_function_at(callback)
                        else None,
                    }
                )
        elif operation == "HLIL_IF" and _op(node.condition) in ("HLIL_CMP_E", "HLIL_CMP_NE"):
            cond = node.condition
            source, constant = (
                (cond.left, _constant(cond.right))
                if _constant(cond.right) is not None
                else (cond.right, _constant(cond.left))
            )
            if constant is not None and is_control(source):
                target = node.true if _op(cond) == "HLIL_CMP_E" else node.false
                row["control_cases"].append(
                    {
                        "input": "Parameters.DeviceIoControl.IoControlCode",
                        "code": constant & 0xFFFFFFFF,
                        "site": hex(target.address - view.start),
                        "evidence": [{"kind": "comparison", "site": site}]
                        + _size_checks(target, view, budget),
                    }
                )
        elif operation == "HLIL_SWITCH":
            if is_control(node.condition):
                for case in node.cases:
                    for value in case.values:
                        code = _constant(value)
                        if code is not None:
                            row["control_cases"].append(
                                {
                                    "input": "Parameters.DeviceIoControl.IoControlCode",
                                    "code": code & 0xFFFFFFFF,
                                    "site": hex(case.body.address - view.start),
                                    "evidence": [{"kind": "switch", "site": site}]
                                    + _size_checks(case.body, view, budget),
                                }
                            )
            else:
                row["unresolved"].append({"reason": "switch input not established", "site": site})
        elif operation in ("HLIL_JUMP", "HLIL_UNDEF", "HLIL_UNIMPL"):
            row["unresolved"].append({"reason": "unsupported control flow", "site": site})
    return row


def _size_checks(node, view, budget):
    checks = []
    for candidate in _walk(node, budget):
        if not _op(candidate).startswith("HLIL_CMP_"):
            continue
        for source, constant in (
            (candidate.left, candidate.right),
            (candidate.right, candidate.left),
        ):
            path, value = _field_path(source), _constant(constant)
            if value is not None and path in (
                "Parameters.DeviceIoControl.InputBufferLength",
                "Parameters.DeviceIoControl.OutputBufferLength",
            ):
                checks.append(
                    {
                        "kind": "conditional_size",
                        "field": path,
                        "value": value,
                        "operator": _op(candidate),
                        "site": hex(candidate.address - view.start),
                    }
                )
                if len(checks) >= 128:
                    return checks + [{"kind": "truncated_size_evidence"}]
    return checks


def _unicode_string(view, address):
    value = view.get_type_by_name("_UNICODE_STRING")
    members = {m.name: m for m in getattr(value, "members", [])}
    if (
        not {"Length", "Buffer"} <= members.keys()
        or members["Length"].type.width != 2
        or members["Buffer"].type.width != view.address_size
    ):
        return None
    try:
        size = view.read_int(address + members["Length"].offset, 2, False)
        pointer = view.read_pointer(address + members["Buffer"].offset)
        if not 0 <= size <= 4096 or size % 2:
            return None
        data = bytes(view.read(pointer, size))
        return data.decode("utf-16le") if len(data) == size else None
    except (ValueError, UnicodeError):
        return None


def _security_arguments(view, name, args):
    result = {
        "sddl_default": None,
        "class_guid": None,
        "device_characteristics": None,
        "symbolic_link": None,
    }

    def constant(index):
        return args[index]["constant"] if index < len(args) else None

    if name in ("IoCreateDevice", "IoCreateDeviceSecure", "WdmlibIoCreateDeviceSecure"):
        result["device_characteristics"] = constant(4)
    if name in ("IoCreateDeviceSecure", "WdmlibIoCreateDeviceSecure"):
        sddl, guid = constant(6), constant(7)
        if sddl is not None:
            result["sddl_default"] = _unicode_string(view, sddl)
        if guid:
            data = bytes(view.read(guid, 16))
            if len(data) == 16:
                result["class_guid"] = str(uuid.UUID(bytes_le=data))
    if name == "IoCreateSymbolicLink" and constant(0) is not None:
        result["symbolic_link"] = _unicode_string(view, constant(0))
    return result
