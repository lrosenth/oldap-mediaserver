#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def make_thumb(video_file: Path, out_file: Path, size: int, overwrite: bool = False) -> None:
    if out_file.exists() and not overwrite:
        print(f"skip  {out_file} (exists)")
        return

    vf = (
        f"thumbnail,"
        f"scale={size}:{size}:force_original_aspect_ratio=decrease,"
        f"pad={size}:{size}:(ow-iw)/2:(oh-ih)/2"
    )

    cmd = [
        "ffmpeg",
        "-y" if overwrite else "-n",
        "-i", str(video_file),
        "-vf", vf,
        "-frames:v", "1",
        str(out_file),
    ]

    print(f"make  {out_file}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        raise RuntimeError(
            f"ffmpeg failed for {video_file} -> {out_file}\n{result.stderr}"
        )


def process_asset_dir(asset_dir: Path, overwrite: bool = False) -> tuple[bool, str]:
    derived_dir = asset_dir / "derived"
    web_mp4 = derived_dir / "web.mp4"

    if not derived_dir.is_dir():
        return False, f"no derived dir: {asset_dir}"

    if not web_mp4.is_file():
        return False, f"no web.mp4: {asset_dir}"

    try:
        make_thumb(web_mp4, derived_dir / "thumb128.jpg", 128, overwrite=overwrite)
        make_thumb(web_mp4, derived_dir / "thumb256.jpg", 256, overwrite=overwrite)
        return True, f"ok: {asset_dir.name}"
    except Exception as exc:
        return False, f"error in {asset_dir.name}: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate video thumbnails for OLDAP media server layout."
    )
    parser.add_argument(
        "root",
        type=Path,
        help="Path to Video/ImageLibrary",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing thumbnails",
    )
    args = parser.parse_args()

    root = args.root.resolve()

    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 2

    ok_count = 0
    fail_count = 0

    for asset_dir in sorted(root.iterdir()):
        if not asset_dir.is_dir():
            continue

        ok, msg = process_asset_dir(asset_dir, overwrite=args.overwrite)
        print(msg)
        if ok:
            ok_count += 1
        else:
            fail_count += 1

    print(f"\nDone. ok={ok_count}, failed={fail_count}")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())