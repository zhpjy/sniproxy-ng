#!/usr/bin/env python3

import argparse
import base64
import hashlib
import json
from pathlib import Path


ASSET_NAMES = {
    "x86_64-linux": "sniproxy-ng-linux-amd64-musl",
    "aarch64-linux": "sniproxy-ng-linux-arm64-musl",
    "x86_64-darwin": "sniproxy-ng-darwin-amd64",
    "aarch64-darwin": "sniproxy-ng-darwin-arm64",
}


def file_sri_sha256(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).digest()
    return f"sha256-{base64.b64encode(digest).decode('ascii')}"


def build_manifest(release_tag: str, artifacts_dir: Path) -> dict:
    version = release_tag.removeprefix("v")
    assets = {}
    for system, asset_name in ASSET_NAMES.items():
        file_name = f"{asset_name}-{release_tag}.tar.gz"
        asset_path = artifacts_dir / file_name
        if not asset_path.exists():
            raise FileNotFoundError(f"missing artifact: {asset_path}")
        assets[system] = {
            "file": file_name,
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
