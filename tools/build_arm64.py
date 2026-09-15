"""Build/package the pinned native CLRBHB fix; explicitly install into a user profile."""

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import tarfile
import urllib.request
from pathlib import Path

SDK_REVISION = "2ddf304b3275aa184e95570404539cbc4beb64c6"
SDK_SHA256 = "4b69063720bdb28e9a6d2bcbbb5dcc5bf38cce0f63f618d9bd614a937161beb1"
FMT_REVISION = "40626af88bd7df9a5fb80be7b25ac85b122d6c21"
FMT_SHA256 = "15b7d9723d16e6ecbf83438a1611a2910879eaa5bc8d0e0fd8197c2f18f993be"
SETTING = "corePlugins.architectures.aarch64"
PLUGIN = "libarch_arm64.dylib"
RECEIPT = "clrbhb-install.json"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compatible(installation):
    revision = installation / "Contents/Resources/api_REVISION.txt"
    found = set(re.findall(r"\b[0-9a-f]{40}\b", revision.read_text()))
    if found != {SDK_REVISION}:
        raise ValueError("replacement requires Binary Ninja 6.0.10601 / pinned SDK revision")


def archive(path, repository, revision, expected):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".download")
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/tarball/{revision}",
            headers={"User-Agent": "binja-windbg-mcp-arm64-builder"},
        )
        try:
            with (
                urllib.request.urlopen(request, timeout=60) as response,
                temporary.open("wb") as out,
            ):
                shutil.copyfileobj(response, out)
            if digest(temporary) != expected:
                raise ValueError("source archive hash mismatch")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    if digest(path) != expected:
        raise ValueError("source archive hash mismatch")
    return path


def extract(path, destination):
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(path) as source:
        for member in source:
            parts = Path(member.name).parts
            if not parts or Path(member.name).is_absolute() or ".." in parts:
                raise ValueError("unsafe source archive path")
            if member.isdir():
                continue
            if not member.isfile() or len(parts) < 2:
                raise ValueError("source archive contains a link or special file")
            target = destination.joinpath(*parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as inp, target.open("wb") as out:
                shutil.copyfileobj(inp, out)


def read_package(package):
    manifest = json.loads((package / "manifest.json").read_text())
    if (
        manifest.get("sdk_revision") != SDK_REVISION
        or manifest.get("core_abi") != 187
        or manifest.get("platform") != "macos-arm64"
        or manifest.get("plugin") != PLUGIN
    ):
        raise ValueError("unsupported ARM64 plugin package")
    if digest(package / PLUGIN) != manifest["plugin_sha256"]:
        raise ValueError("plugin package hash mismatch")
    return manifest


def stopped():
    listing = subprocess.run(["ps", "-axo", "comm="], check=True, text=True, capture_output=True)
    if any(Path(line.strip()).name == "binaryninja" for line in listing.stdout.splitlines()):
        raise ValueError("close Binary Ninja before changing an architecture plugin")


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def install(package, profile, installation):
    compatible(installation)
    manifest = read_package(package)
    stopped()
    profile.mkdir(parents=True, exist_ok=True)
    plugins = profile / "plugins"
    plugins.mkdir(exist_ok=True)
    target, receipt = plugins / PLUGIN, profile / RECEIPT
    if target.exists() or receipt.exists():
        raise ValueError(
            "existing replacement found; uninstall the owned package before replacing it"
        )
    settings_file = profile / "settings.json"
    settings = json.loads(settings_file.read_text()) if settings_file.exists() else {}
    prior = {"present": SETTING in settings, "value": settings.get(SETTING)}
    record = {"manifest": manifest, "previous_setting": prior}
    # Write the ownership record first so an interrupted installation remains removable.
    write_json(receipt, record)
    shutil.copy2(package / PLUGIN, target)
    settings[SETTING] = False
    write_json(settings_file, settings)


def uninstall(profile):
    stopped()
    receipt = profile / RECEIPT
    record = json.loads(receipt.read_text())
    target = profile / "plugins" / PLUGIN
    if target.exists() and digest(target) != record["manifest"]["plugin_sha256"]:
        raise ValueError("installed plugin changed; refusing to remove an unowned file")
    settings_file = profile / "settings.json"
    settings = json.loads(settings_file.read_text()) if settings_file.exists() else {}
    if settings.get(SETTING) is False:
        prior = record["previous_setting"]
        if prior["present"]:
            settings[SETTING] = prior["value"]
        else:
            settings.pop(SETTING, None)
        write_json(settings_file, settings)
    target.unlink(missing_ok=True)
    receipt.unlink()


def build(args):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("this package targets Apple Silicon macOS")
    compatible(args.bn_install)
    root = Path(__file__).resolve().parents[1]
    work = args.build_dir or root / "build/arm64-clrbhb"
    work.mkdir(parents=True, exist_ok=True)
    patch = root / "native/arm64/clrbhb.patch"
    marker = {
        "sdk_revision": SDK_REVISION,
        "patch_sha256": digest(patch),
        "fmt_revision": FMT_REVISION,
    }
    sdk = work / "sdk"
    if sdk.exists():
        if (
            not (work / "source.json").exists()
            or json.loads((work / "source.json").read_text()) != marker
        ):
            raise ValueError("build source differs; choose a new --build-dir")
    else:
        sdk_archive = archive(
            args.sdk_archive or work / "sdk.tar.gz",
            "Vector35/binaryninja-api",
            SDK_REVISION,
            SDK_SHA256,
        )
        fmt_archive = archive(
            args.fmt_archive or work / "fmt.tar.gz", "fmtlib/fmt", FMT_REVISION, FMT_SHA256
        )
        extract(sdk_archive, sdk)
        extract(fmt_archive, sdk / "vendor/fmt")
        subprocess.run(["git", "apply", "--check", str(patch)], cwd=sdk, check=True)
        subprocess.run(["git", "apply", str(patch)], cwd=sdk, check=True)
        write_json(work / "source.json", marker)
    subprocess.run(
        [
            args.cmake,
            "-S",
            str(sdk / "arch/arm64"),
            "-B",
            str(work / "build"),
            "-DCMAKE_BUILD_TYPE=Release",
            "-DHEADLESS=ON",
            "-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0",
            f"-DBN_INSTALL_DIR={args.bn_install.resolve()}",
        ],
        check=True,
    )
    subprocess.run(
        [args.cmake, "--build", str(work / "build"), "--parallel", str(args.jobs)], check=True
    )
    package = root / "dist/arm64-clrbhb-bn6-abi187-macos-arm64"
    package.mkdir(parents=True, exist_ok=True)
    shutil.copy2(work / "build" / PLUGIN, package / PLUGIN)
    shutil.copy2(sdk / "LICENSE.txt", package / "BINARYNINJA_LICENSE.txt")
    shutil.copy2(sdk / "vendor/fmt/LICENSE", package / "FMT_LICENSE.txt")
    shutil.copy2(root / "native/arm64/README.md", package / "README.md")
    write_json(
        package / "manifest.json",
        {
            **marker,
            "core_abi": 187,
            "platform": "macos-arm64",
            "minimum_macos": "13.0",
            "plugin": PLUGIN,
            "plugin_sha256": digest(package / PLUGIN),
            "sdk_archive_sha256": SDK_SHA256,
            "fmt_archive_sha256": FMT_SHA256,
        },
    )
    print(shutil.make_archive(str(package), "zip", package))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bn-install", type=Path, default=Path("/Applications/Binary Ninja.app"))
    parser.add_argument(
        "--cmake", default=shutil.which("cmake") or "/Applications/CMake.app/Contents/bin/cmake"
    )
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--sdk-archive", type=Path)
    parser.add_argument("--fmt-archive", type=Path)
    parser.add_argument("--profile", type=Path, help="Explicit Binary Ninja user directory")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--install", type=Path, metavar="PACKAGE", help="Install a built package into --profile"
    )
    actions.add_argument(
        "--uninstall", action="store_true", help="Remove only this installer's owned plugin"
    )
    args = parser.parse_args()
    if (args.install or args.uninstall) and not args.profile:
        parser.error("installation and removal require an explicit --profile")
    if args.jobs < 1:
        parser.error("jobs must be positive")
    if args.install:
        install(args.install, args.profile, args.bn_install)
    elif args.uninstall:
        uninstall(args.profile)
    else:
        build(args)


if __name__ == "__main__":
    main()
