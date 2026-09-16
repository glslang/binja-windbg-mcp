"""Bump the pinned runtime dependencies, then regenerate the lock and requirements.txt.

Dependabot cannot do this job. It never sees requirements.lock, and requirements.txt is a
flat list of transitive pins with no resolver behind it, so it rewrites those pins one line
at a time and can pin a package away from the parent that requires it. Here uv resolves the
whole set from pyproject.toml, and requirements.txt is derived from the lock that results.
"""

import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Resolve for the supported runtime rather than for whatever machine runs this. Without
# --python-platform a Linux runner drops anything a release gates behind a macOS marker.
COMPILE = [
    "uv",
    "pip",
    "compile",
    "pyproject.toml",
    "--python-version",
    "3.13",
    "--python-platform",
    "aarch64-apple-darwin",
    "--generate-hashes",
    "--upgrade",
    "-o",
    "requirements.lock",
]
PIN = re.compile(r"([A-Za-z0-9._-]+)==([A-Za-z0-9.*+!-]+)")


def compile_lock():
    """Resolve the lock; uv echoes it to stdout as well, so keep only stderr for errors."""
    subprocess.run(COMPILE, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def pins(path):
    """Read the `name==version` pins of a lock or of the plain file, in file order."""
    return [match.group(0) for match in map(PIN.match, path.read_text().splitlines()) if match]


def named(path):
    """Map package name to pinned version."""
    return dict(pin.split("==") for pin in pins(path))


def dependencies(text):
    """Read the exact pins that pyproject.toml declares as direct dependencies."""
    declared = tomllib.loads(text)["project"]["dependencies"]
    for dependency in declared:
        if not PIN.fullmatch(dependency):
            raise SystemExit(f"pyproject.toml: expected an exact pin, found {dependency!r}")
    return declared


def bump(path, lock):
    """Drop the direct pins, resolve, then pin back whatever uv chose.

    uv picks the newest release that still satisfies requires-python for the target
    interpreter. Asking PyPI for its headline version instead would pin a release needing a
    newer interpreter than this project supports, and the resolve after it would then have
    no solution at all.
    """
    pinned = path.read_text()
    relaxed = pinned
    for dependency in dependencies(pinned):
        relaxed = relaxed.replace(f'"{dependency}"', f'"{dependency.split("==")[0]}"')
    path.write_text(relaxed)
    try:
        compile_lock()
    except BaseException:
        path.write_text(pinned)
        raise
    resolved = named(lock)
    text = pinned
    for dependency in dependencies(pinned):
        package = dependency.split("==")[0]
        text = text.replace(f'"{dependency}"', f'"{package}=={resolved[package]}"')
    path.write_text(text)


def sync(lock, requirements):
    """Rewrite the Extension Manager pins from the lock, keeping the leading comment."""
    header = []
    for line in requirements.read_text().splitlines():
        if not line.startswith("#"):
            break
        header.append(line)
    requirements.write_text("\n".join(header + pins(lock)) + "\n")


def report(before, after):
    """Describe the move of every pin that changed, so the pull request says what it does."""
    changes = [
        f"- {package}: {before.get(package, 'new')} to {version}"
        for package, version in after.items()
        if before.get(package) != version
    ]
    changes += [f"- {package}: dropped" for package in before if package not in after]
    return "\n".join(sorted(changes)) if changes else "Runtime dependencies are already current."


def main():
    requirements = ROOT / "requirements.txt"
    before = named(requirements)
    bump(ROOT / "pyproject.toml", ROOT / "requirements.lock")
    sync(ROOT / "requirements.lock", requirements)
    print(report(before, named(requirements)))


if __name__ == "__main__":
    main()
