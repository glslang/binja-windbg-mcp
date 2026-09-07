"""BN6 similarity boundary. Only this module touches native similarity handles."""

from __future__ import annotations

import copy
import time
from pathlib import Path

from .core import Coordinate, Identity
from .similarity import PROVIDERS, SIDES, SimilarityError, require

MAX_FUNCTIONS = 100_000
MAX_INSTRUCTIONS = 2_000


def create_provider(bn, name):
    provider_type = bn.SimilarityProviderType.get(name)
    require(provider_type is not None, "similarity_unavailable", f"provider is unavailable: {name}")
    settings = provider_type.get_default_settings()
    require(
        settings is not None, "similarity_unavailable", f"provider settings unavailable: {name}"
    )
    provider = provider_type.create(settings)
    require(provider is not None, "similarity_unavailable", f"BN6 Ultimate is required for {name}")
    return provider


def function_record(snapshot, address, name):
    base = int(snapshot["image_base"], 16)
    coordinate = Coordinate(
        module=Path(snapshot["image_name"]).stem,
        image_name=snapshot["image_name"],
        identity=Identity.model_validate(snapshot["identity"]),
        rva=hex(address - base),
    )
    coordinate.address(base, coordinate.identity)
    return {
        "binary_id": snapshot["binary_id"],
        "generation": snapshot["generation"],
        "coordinate": coordinate.model_dump(),
        "address": f"0x{address:016x}",
        "name": name[:512],
    }


class NativeSimilarity:
    def __init__(self, workspace, bn=None):
        self.workspace = workspace
        self._bn = bn

    def bn(self):
        if self._bn is None:
            import binaryninja

            return binaryninja
        return self._bn

    def capabilities(self):
        result = {
            "available": False,
            "requires": "Binary Ninja 6 Ultimate",
            "providers": {p: False for p in PROVIDERS},
        }
        try:
            if self.workspace is not None and hasattr(self.workspace, "_check_open"):
                self.workspace._check_open()
            bn = self.bn()
            result["version"] = bn.core_version()
            result["edition"] = bn.core_product_type()
            for name in PROVIDERS:
                try:
                    create_provider(bn, name)
                    result["providers"][name] = True
                except (SimilarityError, AttributeError):
                    pass
        except (ImportError, RuntimeError, AttributeError, InterruptedError):
            result["reason"] = "Binary Ninja similarity API is unavailable in this process"
        result["available"] = any(result["providers"].values())
        return result

    def acquire(self, binary_id, snapshot=None):
        try:
            self.workspace._check_open()
            key, view, active, _ = self.workspace.acquire(binary_id)
        except (ValueError, InterruptedError) as error:
            raise SimilarityError(
                "stale" if snapshot else "invalid_binary", "PE view is closed or unavailable"
            ) from error
        if snapshot is not None:
            require(
                tuple(snapshot["generation"]) == self.workspace.stamp(key, view),
                "stale",
                "view generation changed",
            )
        return key, view, active

    def prepare(self, reference, target, providers, check):
        bn = self.bn()
        views, keys, snapshots, functions = {}, {}, {}, {}
        for side, binary_id in zip(SIDES, (reference, target)):
            check()
            key, view, active = self.acquire(binary_id)
            require(view.view_type == "PE", "invalid_binary", "select open PE views")
            require(
                view.analysis_state.name == "IdleState",
                "analysis_busy",
                "use wait_for_analysis before comparing",
            )
            stamp = self.workspace.stamp(key, view)
            snapshot = self.workspace.metadata(key, view, active)
            functions[side] = {}
            for function in view.functions:
                check()
                require(
                    len(functions[side]) < MAX_FUNCTIONS,
                    "function_limit",
                    "comparison supports at most 100000 functions per view",
                )
                if view.is_valid_offset(function.start):
                    functions[side][function.start] = function_record(
                        snapshot, function.start, function.name
                    )
            require(
                stamp == self.workspace.stamp(key, view),
                "stale",
                "view changed while capturing functions",
            )
            views[side], keys[side], snapshots[side] = view, key, snapshot
        require(
            snapshots["reference"]["architecture"] == snapshots["target"]["architecture"],
            "architecture_mismatch",
            "comparison requires the same architecture",
        )
        session = bn.SimilaritySession()
        instances = {name: create_provider(bn, name) for name in providers}
        for provider in instances.values():
            session.add_provider(provider)
        nodes = {side: bn.SimilaritySessionNode(view) for side, view in views.items()}
        for node in nodes.values():
            session.graph.add_node(node)
        require(
            session.graph.add_edge(nodes["reference"], nodes["target"]),
            "invalid_graph",
            "could not connect comparison nodes",
        )
        # Never add a resolver: it can apply metadata as part of the background run.
        return NativeRun(self, session, nodes, instances, views, keys, snapshots, functions)

    def instructions(self, record, snapshots):
        output, truncated = {}, {}
        acquired = {}
        for side in SIDES:
            snapshot = snapshots[side]
            key, view, _ = self.acquire(snapshot["binary_id"], snapshot)
            address = int(record[side]["address"], 16)
            function = view.get_function_at(address)
            require(function is not None, "stale", "matched function is no longer available")
            acquired[side] = (key, view)
            rows, clipped = [], False
            for index, (tokens, address) in enumerate(function.instructions):
                self.workspace._check_open()
                if index == MAX_INSTRUCTIONS:
                    clipped = True
                    break
                text = "".join(token.text for token in tokens)
                clipped |= len(text) > 1024
                rows.append(
                    {
                        "address": f"0x{address:016x}",
                        "rva": hex(address - view.start),
                        "text": text[:1024],
                        "text_truncated": len(text) > 1024,
                    }
                )
            output[side] = sorted(rows, key=lambda row: int(row["address"], 16))
            truncated[side] = clipped
        for side, (key, view) in acquired.items():
            require(
                tuple(snapshots[side]["generation"]) == self.workspace.stamp(key, view),
                "stale",
                "view changed during instruction capture",
            )
        return output, truncated


class NativeRun:
    def __init__(self, backend, session, nodes, providers, views, keys, snapshots, functions):
        self.backend, self.session = backend, session
        self.nodes, self.providers, self.views = nodes, providers, views
        self.keys = tuple(keys.values())
        self.view_keys = keys
        self.snapshots, self.functions = snapshots, functions
        self.completion = None
        self.unresolved = 0

    def validate(self):
        for side, view in self.views.items():
            require(
                tuple(self.snapshots[side]["generation"])
                == self.backend.workspace.stamp(self.view_keys[side], view),
                "stale",
                "view changed during comparison",
            )

    def start(self):
        self.completion = self.session.run()

    @property
    def finished(self):
        return self.completion is None or self.completion.is_finished

    @property
    def progress(self):
        return self.completion.progress if self.completion is not None else 0.0

    def request_stop(self):
        if self.completion is not None:
            self.completion.request_stop()

    def finish(self):
        if not self.finished:
            self.request_stop()
            while not self.finished:
                time.sleep(0.05)

    def records(self):
        node_sides = {node.id: side for side, node in self.nodes.items()}
        provider_names = {provider.id: name for name, provider in self.providers.items()}
        seen = set()
        for side in SIDES:
            node = self.nodes[side]
            for entity_id in node.entities:
                entity = node.get_entity(entity_id)
                for result_id in node.get_results(entity_id):
                    result = node.get_result(result_id)
                    if result is None or entity is None:
                        self.unresolved += 1
                        continue
                    other_side = node_sides.get(result.target.node_id)
                    if (
                        other_side is None
                        or other_side == side
                        or result.provider_id not in provider_names
                    ):
                        self.unresolved += 1
                        continue
                    target_entity = self.nodes[other_side].get_entity(result.target.entity_id)
                    left = self.functions[side].get(entity.address)
                    right = (
                        self.functions[other_side].get(target_entity.address)
                        if target_entity
                        else None
                    )
                    if left is None or right is None:
                        self.unresolved += 1
                        continue
                    endpoints = {side: left, other_side: right}
                    name = provider_names[result.provider_id]
                    fingerprint = (
                        name,
                        endpoints["reference"]["address"],
                        endpoints["target"]["address"],
                        result.similarity,
                        result.confidence,
                    )
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                    yield {
                        "result_id": f"match_{len(seen)}",
                        "provider": name,
                        "similarity": result.similarity,
                        "confidence": result.confidence,
                        **copy.deepcopy(endpoints),
                    }

    def unmatched(self, records):
        matched = {side: {int(r[side]["address"], 16) for r in records} for side in SIDES}
        return {
            side: [
                copy.deepcopy(self.functions[side][addr])
                for addr in sorted(self.functions[side])
                if addr not in matched[side]
            ]
            for side in SIDES
        }
