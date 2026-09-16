"""Check that requirements.txt pins exactly what the hash-pinned lock resolves to."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPILE = (
    "uv pip compile pyproject.toml --python-version 3.13 "
    "--python-platform aarch64-apple-darwin --generate-hashes -o requirements.lock"
)
PIN = re.compile(r"([A-Za-z0-9._-]+)==([A-Za-z0-9.*+!-]+)")


def name(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def plain(path):
    """Read Extension Manager requirements: one `name==version` line, no pip directives."""
    pins = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        match = PIN.fullmatch(text)
        if not match:
            raise SystemExit(f"{path.name}:{number}: expected a plain pin, found {text!r}")
        pins[name(match.group(1))] = match.group(2)
    return pins


def compiled(path):
    """Read the pins of a uv-compiled lock; hashes and `# via` comments are indented."""
    pins = {}
    for line in path.read_text().splitlines():
        match = PIN.match(line)
        if match:
            pins[name(match.group(1))] = match.group(2)
    return pins


def main():
    requirements = plain(ROOT / "requirements.txt")
    lock = compiled(ROOT / "requirements.lock")
    problems = [
        f"{package}: resolved by the lock but missing from requirements.txt"
        for package in sorted(lock.keys() - requirements.keys())
    ]
    problems += [
        f"{package}: pinned in requirements.txt but not resolved by the lock"
        for package in sorted(requirements.keys() - lock.keys())
    ]
    problems += [
        f"{package}: requirements.txt has {requirements[package]}, lock has {lock[package]}"
        for package in sorted(requirements.keys() & lock.keys())
        if requirements[package] != lock[package]
    ]
    if problems:
        report = [
            "Requirements are out of sync:",
            *problems,
            f"Regenerate the lock with: {COMPILE}",
        ]
        raise SystemExit("\n".join(report))
    print(f"requirements.txt matches requirements.lock ({len(requirements)} packages)")


if __name__ == "__main__":
    main()
