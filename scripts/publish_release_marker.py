from __future__ import annotations

import argparse
import sys
from pathlib import Path

from registry_upload import (
    RegistryUploadError,
    promote_release_marker,
    publish_oci_layout,
)


def write_new_reference(path: Path, reference: str) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(reference + "\n")
    except OSError as error:
        raise RuntimeError("cannot create the immutable marker reference file") from error


def publish_marker(
    image: str,
    registry_host: str,
    layout: Path,
    reference_output: Path,
) -> str:
    reference = publish_oci_layout(layout, image, registry_host)
    write_new_reference(reference_output, reference)
    print("Published the immutable OCI release marker", flush=True)
    return reference


def promote_marker(image: str, registry_host: str, layout: Path) -> str:
    reference = promote_release_marker(layout, image, registry_host)
    print("Promoted the verified OCI release marker to production", flush=True)
    return reference


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Publish and promote a strict OCI release marker"
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)

    publish = subparsers.add_parser("publish")
    publish.add_argument("--image", required=True)
    publish.add_argument("--registry-host", required=True)
    publish.add_argument("--layout", type=Path, required=True)
    publish.add_argument("--reference-output", type=Path, required=True)

    promote = subparsers.add_parser("promote")
    promote.add_argument("--image", required=True)
    promote.add_argument("--registry-host", required=True)
    promote.add_argument("--layout", type=Path, required=True)

    args = parser.parse_args()
    if args.operation == "publish":
        publish_marker(
            args.image,
            args.registry_host,
            args.layout,
            args.reference_output,
        )
    else:
        promote_marker(args.image, args.registry_host, args.layout)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RegistryUploadError, RuntimeError) as error:
        print(f"release marker publication failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
