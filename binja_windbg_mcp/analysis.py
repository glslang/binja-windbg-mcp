"""Conservative driver analysis over immutable adapter captures (format version 1)."""

from collections import deque

from .core import ioctl_case

DRIVER_TOOLS = ("driver_entry", "sink_imports", "device_security", "ioctl_map", "driver_surface")

SINK_VERSION = 1
SINKS = {
    "memcpy": "copy",
    "memmove": "copy",
    "RtlCopyMemory": "copy",
    "RtlMoveMemory": "copy",
    "ProbeForRead": "probe",
    "ProbeForWrite": "probe",
    "MmMapIoSpace": "physical_mapping",
    "MmMapIoSpaceEx": "physical_mapping",
    "MmMapLockedPagesSpecifyCache": "mapping",
    "ZwOpenProcess": "process",
    "ZwOpenThread": "thread",
    "ZwMapViewOfSection": "mapping",
    "ObReferenceObjectByHandle": "handle",
    "ExAllocatePoolWithTag": "allocation",
    "ExAllocatePool2": "allocation",
    "MmGetSystemAddressForMdlSafe": "mdl",
    "IoCreateDevice": "device",
    "IoCreateDeviceSecure": "device_security",
    "WdmlibIoCreateDeviceSecure": "device_security",
    "WdfDeviceCreate": "device",
    "WdfDeviceInitAssignSDDLString": "device_security",
    "IoCreateSymbolicLink": "namespace",
    "WdfDeviceCreateSymbolicLink": "namespace",
}
SECURITY = {
    name for name, kind in SINKS.items() if kind in ("device", "device_security", "namespace")
}


def section(status="success", **data):
    truncated = False
    for key, value in data.items():
        if isinstance(value, list) and len(value) > 1024:
            data[key] = value[:1024]
            truncated = True
    return {"status": "partial" if truncated else status, "truncated": truncated, **data}


def driver_entry(capture, budget):
    roots, unresolved = [], []
    for function in capture["functions"]:
        budget.check()
        for registration in function.get("registrations", []):
            if registration.get("callback_rva") is not None:
                roots.append(registration)
            else:
                unresolved.append(registration)
    kmdf = any(name.startswith("Wdf") for name in capture["imports"])
    if kmdf:
        unresolved.append(
            {
                "framework": "KMDF",
                "reason": "framework table and callback registration require resolved layouts",
            }
        )
    return section(
        "success" if roots and not unresolved else "partial" if roots else "unavailable",
        entry_rva=capture.get("entry_rva"),
        roots=roots,
        unresolved_callbacks=unresolved,
        frameworks=[name for name, present in (("WDM", bool(roots)), ("KMDF", kmdf)) if present],
        prerequisites=capture.get("types", {}),
    )


def sink_imports(capture, budget):
    budget.check()
    return section(
        sink_list_version=SINK_VERSION,
        imports=[
            {"name": name, "category": SINKS[name], "rva": rva}
            for name, rva in capture["imports"].items()
            if name in SINKS
        ],
        limitation="Import presence is not a reachable call; absence does not exclude dynamic resolution or equivalent code.",
    )


def device_security(capture, budget):
    calls = []
    for function in capture["functions"]:
        budget.check()
        for call in function.get("calls", []):
            if call.get("name") in SECURITY:
                calls.append(call)
    return section(
        "partial" if calls else "unavailable",
        creation_and_namespace_calls=calls,
        limitation="Recovered literals and characteristics are static defaults. Effective access and namespace visibility require installation/runtime evidence.",
    )


def ioctl_map(capture, budget, traverse=False, depth=2, function_limit=128):
    if not 0 <= depth <= 8 or not 1 <= function_limit <= 1024:
        raise ValueError("traversal bounds: depth 0–8, functions 1–1024")
    entry = driver_entry(capture, budget)
    roots = {r["callback_rva"] for r in entry["roots"] if r.get("major_function") in (14, 15)}
    functions = {f["rva"]: f for f in capture["functions"]}
    cases, unresolved, paths = [], [], []
    for root in sorted(roots):
        budget.check()
        function = functions.get(root)
        if function is None:
            unresolved.append({"dispatch_rva": root, "reason": "dispatch function unavailable"})
            continue
        for branch in function.get("control_cases", []):
            if branch.get("input") != "Parameters.DeviceIoControl.IoControlCode":
                unresolved.append(
                    {
                        "dispatch_rva": root,
                        "reason": "control-code input not established",
                        "site": branch.get("site"),
                    }
                )
                continue
            cases.append(
                ioctl_case(
                    branch["code"],
                    int(root, 16),
                    int(branch["site"], 16),
                    branch.get("evidence", []),
                )
            )
        unresolved.extend(function.get("unresolved", []))
    visited, truncated = set(), bool(capture.get("truncated"))
    if traverse:
        queue = deque((r, 0, [r]) for r in sorted(roots))
        while queue:
            budget.check()
            rva, level, path = queue.popleft()
            if rva in visited:
                continue
            if len(visited) >= function_limit:
                truncated = True
                break
            visited.add(rva)
            for call in functions.get(rva, {}).get("calls", []):
                if call.get("name") in SINKS:
                    if len(paths) >= 1024:
                        truncated = True
                        queue.clear()
                        break
                    paths.append({"path": path, "site": call["site"], "sink": call["name"]})
                target = call.get("target_rva")
                if target in functions and target not in visited:
                    if level < depth:
                        queue.append((target, level + 1, path + [target]))
                    else:
                        truncated = True
    return section(
        "partial" if unresolved or truncated else "success" if roots else "unavailable",
        cases=cases,
        unresolved=unresolved,
        prerequisites=entry["prerequisites"],
        traversal={
            "enabled": traverse,
            "depth": depth,
            "function_limit": function_limit,
            "visited": len(visited),
            "truncated": truncated,
            "paths": paths,
        },
        limitation="Probe sites record analysis coverage, not safe buffer handling or a vulnerability.",
    )


def driver_surface(capture, budget, depth=2, function_limit=128):
    result = {}
    for name, function in (
        ("driver_entry", driver_entry),
        ("sink_imports", sink_imports),
        ("device_security", device_security),
        ("ioctl_map", ioctl_map),
    ):
        try:
            result[name] = function(
                capture,
                budget,
                **(
                    {"traverse": True, "depth": depth, "function_limit": function_limit}
                    if name == "ioctl_map"
                    else {}
                ),
            )
        except (TimeoutError, InterruptedError) as error:
            result[name] = section("partial", reason=str(error))
        except Exception as error:
            result[name] = section("error", reason=type(error).__name__)
    return result
