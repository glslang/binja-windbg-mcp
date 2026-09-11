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


def current_frame():
    """Use the sole window's selected tab when macOS has deactivated the app."""
    from binaryninjaui import UIContext

    context = UIContext.activeContext()
    if context is None:
        contexts = list(UIContext.allContexts())
        if len(contexts) != 1:
            return None
        context = contexts[0]
    return context.getCurrentViewFrame()


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
        from .similarity import SimilarityManager

        self.similarity = SimilarityManager(self)

    def shutdown(self):
        self._closing.set()
        self.similarity.stop_all(shutdown=True)
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
            def OnAfterCloseFile(self, context, file, frame):
                # BN still lists this file as open while delivering this notification.
                sessions = {view.file.session_id for view in file.getAllDataViews()}
                for key in list(owner._ids):
                    if key[0] in sessions:
                        owner.invalidate(key)
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
        self.similarity.invalidate(key)

    def _views(self):
        if self._closing.is_set():
            return []
        from binaryninjaui import FileContext

        frame = current_frame()
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

            def data_metadata_updated(self, *args):
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
            members = value_type.members
            index = getattr(node, "member_index", None)
            if index is not None:
                if not 0 <= index < len(members):
                    return None
                member = members[index]
                if member.offset != node.offset:
                    return None
            else:
                matches = [member for member in members if member.offset == node.offset]
                if len(matches) != 1:
                    return None
                member = matches[0]
        except (AttributeError, IndexError):
            return None
        prefix = _field_path(source, depth + 1)
        return (prefix + "." if prefix else "") + member.name
    return None


IOCTL_LAYOUT = "_IO_STACK_LOCATION.Parameters.DeviceIoControl"
IOCTL_FIELDS = ("IoControlCode", "InputBufferLength", "OutputBufferLength")


def _member(value_type, name):
    matches = [member for member in getattr(value_type, "members", []) if member.name == name]
    if len(matches) != 1:
        return None
    member = matches[0]
    if not 0 <= member.offset < member.offset + member.type.width <= value_type.width:
        return None
    return member


def _ioctl_layout(stack_type):
    """Read this view's actual layout, including architecture-specific union padding."""
    parameters = _member(stack_type, "Parameters")
    control = _member(parameters.type, "DeviceIoControl") if parameters else None
    if control is None:
        return {}
    fields = {}
    for name in IOCTL_FIELDS:
        member = _member(control.type, name)
        if member is None or member.type.width != 4:
            continue
        if getattr(getattr(member.type, "type_class", None), "name", "") != "IntegerTypeClass":
            continue
        fields[name] = {"offset": parameters.offset + control.offset + member.offset, "size": 4}
    spans = [(field["offset"], field["offset"] + field["size"]) for field in fields.values()]
    if any(a < d and c < b for i, (a, b) in enumerate(spans) for c, d in spans[i + 1 :]):
        return {}
    return fields


def _ioctl_field_path(node, context):
    """Interpret an exact typed read only in an established device-control dispatch."""
    if context is None:
        return None
    stack_type, fields, pointer_size = context
    offset, source = 0, node
    for _ in range(12):
        operation = _op(source)
        if operation not in ("HLIL_STRUCT_FIELD", "HLIL_DEREF_FIELD") or source.offset < 0:
            return None
        offset += source.offset
        if operation == "HLIL_DEREF_FIELD":
            pointer = source.src.expr_type
            if (
                pointer is None
                or getattr(getattr(pointer, "type_class", None), "name", "") != "PointerTypeClass"
                or pointer.width != pointer_size
                or pointer.target != stack_type
            ):
                return None
            for name, field in fields.items():
                if (offset, node.size) == (field["offset"], field["size"]):
                    return "Parameters.DeviceIoControl." + name
            return None
        source = source.src
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
    stack_type = view.get_type_by_name("_IO_STACK_LOCATION")
    ioctl_fields = _ioctl_layout(stack_type)
    if "IoControlCode" in ioctl_fields:
        layouts[IOCTL_LAYOUT] = ioctl_fields
    else:
        missing.append(IOCTL_LAYOUT)
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
    # Union offsets have meaning only after the WDM device-control roots are established.
    registrations = {}
    for row in result["functions"]:
        for registration in row.get("registrations", []):
            callback = registration.get("callback_rva")
            if callback:
                registrations.setdefault(callback, set()).add(registration.get("major_function"))
    # A shared create/control routine needs path-sensitive major-function proof first.
    roots = {callback for callback, majors in registrations.items() if majors <= {14, 15}}
    if "IoControlCode" in ioctl_fields:
        context = (stack_type, ioctl_fields, view.address_size)
        for index, row in enumerate(result["functions"]):
            if row["rva"] not in roots:
                continue
            if (
                sum(
                    len(item.get(key, []))
                    for item in result["functions"]
                    for key in ("registrations", "control_cases", "calls", "unresolved")
                )
                >= 4096
            ):
                result["truncated"] = True
                result["capture_stop"] = "function fact limit during typed IOCTL recovery"
                break
            try:
                budget.check()
                function = view.get_function_at(view.start + int(row["rva"], 16))
                if function is not None:
                    result["functions"][index] = _capture_function(
                        view, function, layouts, budget, ioctl_context=context
                    )
            except (TimeoutError, InterruptedError) as error:
                result["truncated"] = True
                result["capture_stop"] = str(error)
                break
            except Exception as error:
                row["unresolved"].append(
                    {
                        "reason": "typed IOCTL recovery unavailable",
                        "error_type": type(error).__name__,
                    }
                )
    return result


def _following_statement(node):
    """Find structured fallthrough without crossing a loop or function boundary."""
    for _ in range(12):
        parent = getattr(node, "parent", None)
        if _op(parent) == "HLIL_BLOCK":
            body = parent.body
            index = next(
                (
                    i
                    for i, child in enumerate(body)
                    if child is node or child.expr_index == node.expr_index
                ),
                None,
            )
            if index is None:
                return None
            if index + 1 < len(body):
                return body[index + 1]
        elif _op(parent) != "HLIL_IF":
            return None
        node = parent
    return None


def _case_target(target, branch, il, base, budget):
    evidence = []
    for _ in range(12):
        budget.check()
        if _op(target) == "HLIL_NOP" or (
            _op(target) == "HLIL_BLOCK" and getattr(target, "body", None) == []
        ):
            target = _following_statement(branch)
            if target is None:
                return None, evidence
            evidence.append({"kind": "fallthrough", "site": hex(branch.address - base)})
            branch = target
        elif _op(target) == "HLIL_BLOCK" and getattr(target, "body", None):
            target = target.body[0]
            branch = target
        elif _op(target) == "HLIL_GOTO":
            label = il.get_label(target.target.label_id)
            if label is None or _op(label) != "HLIL_LABEL":
                return None, evidence
            evidence.append(
                {
                    "kind": "goto_target",
                    "site": hex(target.address - base),
                    "target_rva": hex(label.address - base),
                }
            )
            return label, evidence
        else:
            return target, evidence
    return None, evidence


def _capture_function(view, function, layouts, budget, ioctl_context=None):
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

    def field_path(node):
        return _ioctl_field_path(node, ioctl_context) or _field_path(node)

    # Track immutable initializations by identity, never by a user-controlled display name.
    inputs = set()
    from itertools import islice

    nodes = list(islice(_walk(il.root, budget), 50001))
    if len(nodes) > 50000:
        row["unresolved"].append({"reason": "function IL node cap"})
        return row
    for node in nodes:
        if (
            _op(node) == "HLIL_VAR_INIT"
            and field_path(node.src) == "Parameters.DeviceIoControl.IoControlCode"
        ):
            inputs.add(node.dest.identifier)

    for node in nodes:
        if _op(node) == "HLIL_ASSIGN" and _op(node.dest) == "HLIL_VAR":
            inputs.discard(node.dest.var.identifier)

    def is_control(node):
        return field_path(node) == "Parameters.DeviceIoControl.IoControlCode" or (
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
                body = node.true if _op(cond) == "HLIL_CMP_E" else node.false
                target, flow = _case_target(
                    body,
                    node,
                    il,
                    view.start,
                    budget,
                )
                if target is None:
                    row["unresolved"].append(
                        {"reason": "case destination unavailable", "site": site, "code": constant}
                    )
                    continue
                row["control_cases"].append(
                    {
                        "input": "Parameters.DeviceIoControl.IoControlCode",
                        "code": constant & 0xFFFFFFFF,
                        "site": hex(target.address - view.start),
                        "evidence": [{"kind": "comparison", "site": site}]
                        + flow
                        + _size_checks(body, view, budget, field_path),
                    }
                )
        elif operation == "HLIL_SWITCH":
            if is_control(node.condition):
                for case in node.cases:
                    target, flow = _case_target(case.body, node, il, view.start, budget)
                    if target is None:
                        row["unresolved"].append(
                            {"reason": "switch case destination unavailable", "site": site}
                        )
                        continue
                    for value in case.values:
                        code = _constant(value)
                        if code is not None:
                            row["control_cases"].append(
                                {
                                    "input": "Parameters.DeviceIoControl.IoControlCode",
                                    "code": code & 0xFFFFFFFF,
                                    "site": hex(target.address - view.start),
                                    "evidence": [{"kind": "switch", "site": site}]
                                    + flow
                                    + _size_checks(case.body, view, budget, field_path),
                                }
                            )
            else:
                row["unresolved"].append({"reason": "switch input not established", "site": site})
        elif operation in ("HLIL_JUMP", "HLIL_UNDEF", "HLIL_UNIMPL"):
            row["unresolved"].append({"reason": "unsupported control flow", "site": site})
    return row


def _size_checks(node, view, budget, field_path=_field_path):
    checks = []
    for candidate in _walk(node, budget):
        if not _op(candidate).startswith("HLIL_CMP_"):
            continue
        for source, constant in (
            (candidate.left, candidate.right),
            (candidate.right, candidate.left),
        ):
            path, value = field_path(source), _constant(constant)
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
