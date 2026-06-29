#!/usr/bin/env python3

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path


ASSET_PATTERNS = {
    "x86_64-linux": re.compile(r"^sniproxy-ng-linux-amd64-musl-(?P<tag>v.+)\.tar\.gz$"),
    "aarch64-linux": re.compile(r"^sniproxy-ng-linux-arm64-musl-(?P<tag>v.+)\.tar\.gz$"),
    "aarch64-darwin": re.compile(r"^sniproxy-ng-darwin-arm64-(?P<tag>v.+)\.tar\.gz$"),
}


def file_sri_sha256(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).digest()
    return f"sha256-{base64.b64encode(digest).decode('ascii')}"


def collect_release_assets(release_tag: str, artifacts_dir: Path) -> dict[str, Path]:
    assets = {}

    for asset_path in artifacts_dir.iterdir():
        if not asset_path.is_file():
            continue

        for system, pattern in ASSET_PATTERNS.items():
            match = pattern.match(asset_path.name)
            if not match or match.group("tag") != release_tag:
                continue

            if system in assets:
                raise ValueError(f"duplicate artifact for {system}: {asset_path.name}")

            assets[system] = asset_path
            break

    missing_systems = [system for system in ASSET_PATTERNS if system not in assets]
    if missing_systems:
        missing = ", ".join(missing_systems)
        raise FileNotFoundError(
            f"missing release artifacts for systems: {missing} in {artifacts_dir}"
        )

    return dict(sorted(assets.items()))


def build_manifest(release_tag: str, artifacts_dir: Path) -> dict:
    version = release_tag.removeprefix("v")
    assets = {}
    for system, asset_path in collect_release_assets(release_tag, artifacts_dir).items():
        assets[system] = {
            "file": asset_path.name,
            "hash": file_sri_sha256(asset_path),
        }
    return {
        "releaseVersion": version,
        "assets": assets,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Update release-assets.json from built release archives."
    )
    parser.add_argument("--release-tag", required=True, help="Release tag, e.g. v1.2.3")
    parser.add_argument(
        "--artifacts-dir",
        default="artifacts",
        help="Directory containing built release archives",
    )
    parser.add_argument(
        "--manifest",
        default="release-assets.json",
        help="Path to release manifest JSON file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the updated manifest instead of writing it",
    )
    args = parser.parse_args()

    if not args.release_tag.startswith("v"):
        raise SystemExit("release tag must start with 'v'")

    manifest = build_manifest(args.release_tag, Path(args.artifacts_dir))
    manifest_json = json.dumps(manifest, indent=2) + "\n"

    if args.dry_run:
        print(manifest_json, end="")
        return 0

    Path(args.manifest).write_text(manifest_json, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
