"""Build/package the optional BN6 export helper; never installs into the application."""

import argparse
import shutil
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bn-install", type=Path, default=Path("/Applications/Binary Ninja.app"))
    parser.add_argument(
        "--sdk", type=Path, help="Existing checkout of the pinned SDK with submodules"
    )
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument(
        "--deployment-target", default="13.0", help="Minimum macOS version (default: 13.0)"
    )
    parser.add_argument("--package", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = root / "build/binexport"
    command = [
        args.cmake,
        "-S",
        str(root / "native/binexport"),
        "-B",
        str(build),
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_OSX_DEPLOYMENT_TARGET={args.deployment_target}",
        f"-DBN_INSTALL_DIR={args.bn_install.resolve()}",
        f"-DCMAKE_INSTALL_PREFIX={root}",
    ]
    if args.sdk:
        command.append(f"-DFETCHCONTENT_SOURCE_DIR_BNAPI={args.sdk.resolve()}")
    subprocess.run(command, check=True)
    subprocess.run(
        [
            args.cmake,
            "--build",
            str(build),
            "--target",
            "binja_binexport",
            "--parallel",
            str(args.jobs),
        ],
        check=True,
    )
    subprocess.run([args.cmake, "--install", str(build)], check=True)
    if args.package:
        (root / "dist").mkdir(exist_ok=True)
        archive = shutil.make_archive(
            str(root / "dist/binexport-bn6-abi187-macos-arm64"),
            "zip",
            root,
            "binja_windbg_mcp/native",
        )
        print(archive)


if __name__ == "__main__":
    main()
