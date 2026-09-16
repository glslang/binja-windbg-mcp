"""Bump the pinned runtime dependencies, then regenerate the lock and requirements.txt.

Dependabot cannot do this job. It never sees requirements.lock, and requirements.txt is a
flat list of transitive pins with no resolver behind it, so it rewrites those pins one line
at a time and can pin a package away from the parent that requires it. Here uv resolves the
whole set from pyproject.toml, and requirements.txt is derived from the lock that results.
"""

import json
import re
import subprocess
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPILE = [
    "uv",
    "pip",
    "compile",
    "pyproject.toml",
    "--python-version",
    "3.13",
    "--generate-hashes",
    "--upgrade",
    "-o",
    "requirements.lock",
]
PIN = re.compile(r"([A-Za-z0-9._-]+)==([A-Za-z0-9.*+!-]+)")


def latest(package):
    """Ask PyPI for the newest release of a package."""
    url = f"https://pypi.org/pypi/{package}/json"
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)["info"]["version"]


def bump(path):
    """Move every exact pin in project.dependencies to the newest release on PyPI."""
    text = path.read_text()
    for dependency in tomllib.loads(text)["project"]["dependencies"]:
        match = PIN.fullmatch(dependency)
        if not match:
            raise SystemExit(f"{path.name}: expected an exact pin, found {dependency!r}")
        package, current = match.group(1), match.group(2)
        newest = latest(package)
        if newest != current:
            text = text.replace(f'"{package}=={current}"', f'"{package}=={newest}"')
    path.write_text(text)


def pins(path):
    """Read the `name==version` pins a uv-compiled lock resolves to, in lock order."""
    return [match.group(0) for match in map(PIN.match, path.read_text().splitlines()) if match]


def sync(lock, requirements):
    """Rewrite the Extension Manager pins from the lock, keeping the leading comment."""
    header = []
    for line in requirements.read_text().splitlines():
        if not line.startswith("#"):
            break
        header.append(line)
    requirements.write_text("\n".join(header + pins(lock)) + "\n")


def main():
    before = pins(ROOT / "requirements.txt")
    bump(ROOT / "pyproject.toml")
    # uv echoes the compiled lock to stdout as well as writing it; keep stderr for errors.
    subprocess.run(COMPILE, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    sync(ROOT / "requirements.lock", ROOT / "requirements.txt")
    after = pins(ROOT / "requirements.txt")

    versions = dict(pin.split("==") for pin in before)
    moved = [pin.split("==") for pin in after if pin not in before]
    changes = [
        f"- {package}: {versions.get(package, 'new')} to {version}" for package, version in moved
    ]
    changes += [
        f"- {package}: dropped"
        for package in versions
        if package not in dict(pin.split("==") for pin in after)
    ]
    print("\n".join(changes) if changes else "Runtime dependencies are already current.")


if __name__ == "__main__":
    main()
