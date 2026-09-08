"""Backend discovery and selection, independent of comparison execution."""

from .similarity import PROVIDERS, SimilarityError
from .similarity_adapter import NativeSimilarity
from .similarity_external import ExternalSimilarity


class SimilarityBackends:
    def __init__(self, workspace):
        self.backends = {
            "native": NativeSimilarity(workspace),
            "external": ExternalSimilarity(workspace),
        }

    def configure(self, path, error=None):
        self.backends["external"].configure(path, error)

    def capabilities(self):
        backends = {name: backend.capabilities() for name, backend in self.backends.items()}
        return {
            "available": any(b["available"] for b in backends.values()),
            "providers": {
                p: any(b["providers"].get(p) for b in backends.values()) for p in PROVIDERS
            },
            "backends": backends,
        }

    def select(self, selection, providers):
        capabilities = self.capabilities()["backends"]
        candidates = ("native", "external") if selection == "auto" else (selection,)
        for name in candidates:
            requested = tuple(
                providers
                if providers is not None
                else (PROVIDERS if name == "native" else PROVIDERS[:1])
            )
            cap = capabilities[name]
            if cap["available"] and all(cap["providers"].get(p) for p in requested):
                return name, self.backends[name], requested
        reasons = "; ".join(
            f"{name}: {(capabilities[name].get('reason') or capabilities[name].get('requires') or 'requested providers unavailable')}"
            for name in candidates
        )
        raise SimilarityError(
            "similarity_unavailable", "Requested providers " + str(providers) + ": " + reasons
        )
